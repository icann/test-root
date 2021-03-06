#!/usr/bin/env python3
''' Program to create a private root zone for testing, with all the trimmings. '''
import configparser, os, re, shutil, subprocess, sys, time

# Constants
LOG_F = open("log_for_make_test_root.txt", mode="a")
ORIG_NAME = "root.zone.original"
UNSIGNED_FILE_NAME = "root.zone.unsigned"
TRUST_ANCHOR_DS_FILE_NAME = "trust-anchor-ds"
TRUST_ANCHOR_DNSKEY_FILE_NAME = "trust-anchor-dnskey"
ROOT_HINTS_FILE_NAME = "root.hints"
BIND_TRUSTED_KEYS_NAME = "bind-trusted-keys"
PDNS_TRUSTED_KEYS_NAME = "pdns-lua"
DEFAULT_NAMESERVER_NAME_SUFFIX = "some-servers.p53"
DEFAULT_BIN_PREFIX = "/usr/sbin"

# The types of signatures that are allowed
#   This is a mapping for BIND's signing function. Others can be added easily.
ALLOWED_SIGNATURE_TYPES = {
	"rsa2048": "-a RSASHA256 -b 2048",
	"rsa4096": "-a RSASHA256 -b 4096",
	"rsa2048sha512": "-a RSASHA512 -b 2048",
	"rsa4096sha512": "-a RSASHA512 -b 4096",
	"gost": "-a ECCGOST",
	"ecdsa256": "-a ECDSAP256SHA256",
	"ecdsa384": "-a ECDSAP384SHA384",
	"eddsa": "-a ED25519",
	"ed448": "-a ED448"
}

# Boring functions
def log(log_message):
	''' log to the main log '''
	LOG_F.write("{}: {}\n".format(time.strftime("%Y-%m-%d-%H-%M-%S"), log_message))

def log_and_print(log_message):
	''' log, then print to the user '''
	print("{}: {}".format(time.strftime("%Y-%m-%d-%H-%M-%S"), log_message))
	log(log_message)

def die(in_str):
	''' log, print, then exit  '''
	err_str = in_str + " Exiting."
	log_and_print(err_str)
	exit()

def get_crypto(in_type):
	''' Returns the BIND string for the algorithm and length from a type '''
	if in_type not in ALLOWED_SIGNATURE_TYPES:
		die("Unknown signature type '{}' was given. Choose from {}.".format(in_type, " ".join(ALLOWED_SIGNATURE_TYPES.keys())))
	return ALLOWED_SIGNATURE_TYPES[in_type]

if __name__ == "__main__":
	''' Main program '''
	start_dir = os.getcwd()
	log("Starting new run; in {}".format(start_dir))

	# Get the command line arguments
	if len(sys.argv) < 2:
		die("You must specify a configuration file as the first argument on the command line.")
	config_file = sys.argv[1]
	if not os.path.exists(config_file):
		die("Could not find the configuration file '{}'.".format(config_file))

	# Get the cotents of the config file
	log("Config file is {}".format(config_file))
	confpar = configparser.ConfigParser()
	config = {}
	try:
		confpar.read(config_file)
	except Exception as this_e:
		die("Reading the configuration file '{}' died with '{}'.".format(config_file, this_e))
	if not confpar.has_section("confs"):
		die("The configuration file had no 'confs' section.")
	for this_option in confpar.options("confs"):
		config[this_option] = confpar.get("confs", this_option)
	log("config is '{}'".format(config))

	# Make sure the required options exist
	target_dir_in = config.get("directory")
	if not target_dir_in:
		die("The 'directory' option did not exist in the configuration.")
	if " " in target_dir_in:
		die("Cannot reliably create output directories with spaces in their names.")
	if not (config.get("ipv4") or config.get("ipv6")):
		die("One or both of 'ipv4' and/or 'ipv6' must be given in the config file.")

	# Get the prefix for the binaries
	binary_prefix = config.get("bin-prefix", DEFAULT_BIN_PREFIX)
	# Sanity check that bindutils are installed
	if not os.path.exists("{}/named-checkconf".format(binary_prefix)):
		die("Could not find named-checkconf in {}. See the README.".format(binary_prefix))

	# Get the nameserver name and parts
	nameserver_suffix = config.get("suffix", DEFAULT_NAMESERVER_NAME_SUFFIX)
	nameserver_name_suffix_parts = nameserver_suffix.split(".")
	if len(nameserver_name_suffix_parts) != 2:
		die("The name server suffix must have exactly two labels; {} was given.".format(nameserver_suffix))
	nameserver_name_suffix_tld = nameserver_name_suffix_parts[-1]
	log("Nameserver suffix is {}".format(nameserver_suffix))

	# Determine the v4 and v6 addresses to listen on
	v4_addr_text = config.get("ipv4")
	if v4_addr_text:
		v4_addrs = v4_addr_text.split(" ")
	else:
		v4_addrs = []
	v6_addr_text = config.get("ipv6")
	if v6_addr_text:
		v6_addrs = v6_addr_text.split(" ")
	else:
		v6_addrs = []
	log_and_print("Found addresses '{}' and '{}'".format(" ".join(v4_addrs), " ".join(v6_addrs)))

	# Create new KSK and ZSK keys
	ksk_type = config.get("ksk-type", "rsa2048")
	ksk_crypto_args = get_crypto(ksk_type)
	number_of_ksks = config.get("ksk-number", "1")  # Comes in as a string
	number_of_ksks = int(number_of_ksks)
	zsk_type = config.get("zsk-type", "rsa2048")
	zsk_crypto_args = get_crypto(zsk_type)
	number_of_zsks = config.get("zsk-number", "1")  # Comes in as a string
	number_of_zsks = int(number_of_zsks)

	# If wrong-trust-anchor is set, ksk-number must be greater than 1
	use_wrong_trust_anchor = config.get("wrong-trust-anchor")
	if use_wrong_trust_anchor and (number_of_ksks <= 1):
		die("Setting wrong-trust-anchor requires ksk-number to be greater than 1.")
	
	# Get the TTL for various SOAs and the RRSIGs
	soa_ttl = config.get("ttl-for-soa", 86400)
	
	### Create a directory for holding the files associated with the root zone being created
	target_dir = target_dir_in
	# If the path given for the target_dir does not start with a /, put it in the same directory as the config file
	if not target_dir.startswith("/"):
		path_to_config_file = os.path.abspath(os.path.split(config_file)[0])
		log("The path to the config file is {}".format(path_to_config_file))
		target_dir = "{}/{}".format(path_to_config_file, target_dir)
	if os.path.exists(target_dir):
		moved_target_dir = "{}-{}".format(target_dir, time.strftime("%Y%m%d%H%M%S"))
		try:
			shutil.move(target_dir, moved_target_dir)
		except Exception as this_e:
			die("Could not move '{}' to '{}': {}.".format(target_dir, moved_target_dir, this_e))
		log_and_print("The directory '{}' already exists; it was moved to '{}'.".format(target_dir, moved_target_dir))
	try:
		os.mkdir(target_dir)
	except Exception as this_e:
		die("Could not create '{}' directory: {}.".format(target_dir, this_e))
	log_and_print("Created directory {}".format(target_dir))
	os.chdir(target_dir)

	### Get the current root zone master file
	try:
		subprocess.check_call("wget -q -O {} http://www.internic.net/domain/root.zone".format(ORIG_NAME), shell=True)
	except Exception as this_e:
		die("When trying to AXFR the root zone, failed with {}.".format(this_e))
	# Sanity check the results
	if not os.path.exists(ORIG_NAME):
		die("Getting the root zone didn't actually get a file.")
	if os.path.getsize(ORIG_NAME) < 2000000:
		die("Getting the root zone resulted in a file that seems too short.")
	log("Got the original root zone")

	### Make the name server names; include the trailing periods
	all_server_full_names = []
	for this_letter in "abcdefghijklm":
		all_server_full_names.append("{}.{}.".format(this_letter, nameserver_suffix))

	# Save the file names as the key files are produced
	ksk_file_names = []  # Just the KSKs
	zsk_file_names = []  # Just the ZSKs
	# Make the KSK and ZSK files
	for _ in range(number_of_ksks):
		ksk_keygen_command = "{0}/dnssec-keygen -f KSK {1} -n ZONE -L {2} .".format(binary_prefix, ksk_crypto_args, soa_ttl)
		this_output = subprocess.getoutput(ksk_keygen_command)
		log("Output of '{}':\n{}".format(ksk_keygen_command, this_output))
		first_line_of_output = (this_output.splitlines())[-1]
		if "fatal" in first_line_of_output:
			die("Failed to make the KSK keys: {}".format(first_line_of_output))
		ksk_file_names.append(first_line_of_output)
	for _ in range(number_of_zsks):
		zsk_keygen_command = "{0}/dnssec-keygen {1} -n ZONE -L {2} .".format(binary_prefix, zsk_crypto_args, soa_ttl)
		this_output = subprocess.getoutput(zsk_keygen_command)
		log("Output of '{}':\n{}".format(zsk_keygen_command, this_output))
		first_line_of_output = (this_output.splitlines())[-1]
		if "fatal" in first_line_of_output:
			die("Failed to make the ZSK keys: {}".format(first_line_of_output))
		zsk_file_names.append(first_line_of_output)
	log_and_print("The {} KSKs are {}".format(len(ksk_file_names), " ".join(ksk_file_names)))
	log_and_print("The {} ZSKs are {}".format(len(zsk_file_names), " ".join(zsk_file_names)))
	# Pick which KSK to use as the trust anchor
	#   If use_wrong_trust_anchor, use the second one instead of the first
	if use_wrong_trust_anchor:
		ksk_for_trust_anchor_file = ksk_file_names[1]
	else:
		ksk_for_trust_anchor_file = ksk_file_names[0]
	# Write out the trust anchor DNSKEY file
	for this_line in open("{}.key".format(ksk_for_trust_anchor_file), mode="rt"):
		if this_line.startswith("."):
			ksk_for_trust_anchor = this_line.strip()
			break
	log("The trust anchor value is {}".format(ksk_for_trust_anchor))
	this_return_text = subprocess.getoutput("{}/dnssec-dsfromkey -2 {}.key >{}"
			.format(binary_prefix, ksk_for_trust_anchor_file, TRUST_ANCHOR_DS_FILE_NAME))
	if "fatal" in this_return_text:
		die("Could not run dnssec-dsfromkey on '{}': '{}'.".format(ksk_for_trust_anchor_file, this_return_text))
	trust_anchor_dnskey_f = open(TRUST_ANCHOR_DNSKEY_FILE_NAME, mode="wt")
	trust_anchor_dnskey_f.write("{}\n".format(ksk_for_trust_anchor))
	trust_anchor_dnskey_f.close()
	log("Wrote out {}".format(TRUST_ANCHOR_DNSKEY_FILE_NAME))
	if use_wrong_trust_anchor:
		log_and_print("   Note that this is purposely the *wrong* trust anchor.")

	### Make keys for signing the root zone server name if it has at least one name under it
	#   This would be signing .net for root-servers.net in the real zone
	#   We need to do this part now so that we can add the DS record of the KSK to the root zone if we are signing the new TLD
	log("Making KSK for {}".format(nameserver_name_suffix_tld))
	# As a shortcut, use the same signing type as the KSK
	this_return_text = subprocess.getoutput("{0}/dnssec-keygen {1} -f KSK -n ZONE -L {2} {3}."\
		.format(binary_prefix, ksk_crypto_args, soa_ttl, nameserver_name_suffix_tld))
	if "fatal" in this_return_text:
		die("Was not able to create nameserver KSK: '{}'.".format(this_return_text))
	nameserver_tld_ksk_file_name = (this_return_text.splitlines())[-1]
	# Get the DNSKEY of this new key, for inclusion in the root zone
	for this_line in open("{}.key".format(nameserver_tld_ksk_file_name), mode="rt"):
		if this_line.startswith("{}.".format(nameserver_name_suffix_tld)):
			nameserver_signing_key_value = this_line.strip()
			break
	log("The KSK for {} is {}".format(nameserver_name_suffix_tld, nameserver_signing_key_value))
	nameserver_ds_file = "{}.ds".format(nameserver_tld_ksk_file_name)
	this_return_text = subprocess.getoutput("{}/dnssec-dsfromkey -2 {}.key >{}".format(binary_prefix, nameserver_tld_ksk_file_name, nameserver_ds_file))
	if "fatal" in this_return_text:
		die("Could not run dnssec-dsfromkey on '{}': '{}'.".format(nameserver_tld_ksk_file_name, this_return_text))
	namenameserver_tld_ds_record = open(nameserver_ds_file, mode="rt").read()
	log("Making ZSK for {}".format(nameserver_name_suffix_tld))
	# As a shortcut, use the same signing type as the KSK
	this_return_text = subprocess.getoutput("{0}/dnssec-keygen {1} -n ZONE -L {2} {3}."\
		.format(binary_prefix, ksk_crypto_args, soa_ttl, nameserver_name_suffix_tld))
	if "fatal" in this_return_text:
		die("Was not able to create nameserver ZSK: '{}'.".format(this_return_text))
	nameserver_tld_zsk_file_name = (this_return_text.splitlines())[-1]

	### Make a new root zone file
	# Get the contents into a string so we can fix them
	zone_content = open(ORIG_NAME, mode="rt").read()
	# Collapse all tabs and multiple spaces into single spaces
	zone_content = re.sub(r'[\t ]+', ' ', zone_content)
	root_zone_lines = zone_content.splitlines()
	# Change the SOA to end in "99"
	if "SOA" not in root_zone_lines[0]:
		die("The first line of the root zone file didn't contain 'SOA'.")
	soa_line_parts = (root_zone_lines[0]).split(" ")
	in_soa = soa_line_parts[6]
	log("Incoming root zone SOA is {}".format(in_soa))
	new_soa_value = in_soa[:-2] + "99"
	root_zone_lines[0] = ". {0} IN SOA a.{1}. foo.{1}. {2} 1800 900 604800 {0}".format(soa_ttl, nameserver_suffix, new_soa_value)
	# Remove the original DNSKEY, RRSIG, and NSEC records
	root_zone_lines = [x for x in root_zone_lines if (x.split(" "))[3] != "DNSKEY"]
	root_zone_lines = [x for x in root_zone_lines if (x.split(" "))[3] != "RRSIG"]
	root_zone_lines = [x for x in root_zone_lines if (x.split(" "))[3] != "NSEC"]
	# Add the new DNSKEY records
	for this_file in (ksk_file_names + zsk_file_names):
		in_lines = open(this_file + ".key", mode="rt").readlines()
		root_zone_lines.append((in_lines[-1]).strip())
	# Remove the original NS records for the root
	root_zone_lines = [x for x in root_zone_lines if not x.startswith(". 518400 IN NS")]
	# Add in the new root NS records
	root_zone_lines.extend([". {0} IN NS {1}".format(soa_ttl, x) for x in all_server_full_names])
	# Be authoritative for the name server: add NS records for the nameserver TLD and full name
	root_zone_lines.extend(["{0}. {1} IN NS {2}".format(nameserver_name_suffix_tld, soa_ttl, x) for x in all_server_full_names])
	root_zone_lines.extend(["{0}. {1} IN NS {2}".format(nameserver_suffix, soa_ttl, x) for x in all_server_full_names])
	# Add the DS record for nameserver TLD
	root_zone_lines.append(namenameserver_tld_ds_record.strip())
	# Create address records for the name servers
	#   Need enough addresses for the 13 name servers.
	#   If the list of addresses is shorter than 13, keep repeating it until it is 13 or longer, then shorten to 13
	nameserver_address_records = []
	if v4_addrs:
		while len(v4_addrs) < 13:
			v4_addrs.extend(v4_addrs)
		v4_addrs = v4_addrs[:13]
		nameserver_address_records.extend(["{0} {1} IN A {2}"\
			.format(all_server_full_names[x], soa_ttl, v4_addrs[x]) for x in range(len(all_server_full_names))])
	if v6_addrs:
		while len(v6_addrs) < 13:
			v6_addrs.extend(v6_addrs)
		v6_addrs = v6_addrs[:13]
		nameserver_address_records.extend(["{0} {1} IN AAAA {2}"\
			.format(all_server_full_names[x], soa_ttl, v6_addrs[x]) for x in range(len(all_server_full_names))])
	root_zone_lines.extend(nameserver_address_records)
	# Put it all together
	root_zone_content = "\n".join(root_zone_lines) + "\n"
	root_f = open(UNSIGNED_FILE_NAME, mode="wt")
	root_f.write(root_zone_content)
	root_f.close()
	# Sanity check the resulting zone
	this_return_text = subprocess.getoutput("named-checkzone -q -i local . {} >/dev/null".format(UNSIGNED_FILE_NAME))
	if "fatal" in this_return_text:
		die("Sanity-checking the unsigned root zone before signing died with '{}'.".format(this_return_text))

	### Sign the root zone
	root_signing_cmd = "{0}/dnssec-signzone -e 20300101000000 -o . -f root.zone {1} {2} >/dev/null"\
		.format(binary_prefix, UNSIGNED_FILE_NAME, " ".join(ksk_file_names + zsk_file_names))
	this_return_text = subprocess.getoutput(root_signing_cmd)
	if "fatal" in this_return_text:
		die("Signing the . zone failed with '{}'.".format("\n".join(this_return_text.splitlines()[-2:])))
	log("Signed the root zone with '{}'".format(root_signing_cmd))
	# Sanity check the signed zone
	this_return_text = subprocess.getoutput("{}/dnssec-verify -o . root.zone 2>/dev/null".format(binary_prefix))
	if "fatal" in this_return_text:
		die("Sanity-checking the signed root zone died with '{}'.".format(this_return_text))
	log("Wrote out signed and verified root.zone")

	### Make the zone for the nameserver
	nameserver_tld_content_lines = []
	# Give it the same SOA as from the root zone
	nameserver_tld_content_lines.append("{0}. {1} IN SOA a.{0}. foo.{0}. {2} 1800 900 604800 {1}"\
		.format(nameserver_name_suffix_tld, soa_ttl, new_soa_value))
	# Add the NS records
	nameserver_tld_content_lines.extend(["{0}. {1} IN NS {2}".format(nameserver_name_suffix_tld, soa_ttl, x) for x in all_server_full_names])
	# Add the DNSKEY records
	nameserver_tld_content_lines.append(open("{}.key".format(nameserver_tld_ksk_file_name), mode="rt").read())
	nameserver_tld_content_lines.append(open("{}.key".format(nameserver_tld_zsk_file_name), mode="rt").read())
	# Add delegation
	nameserver_tld_content_lines.extend(["{0}. {1} IN NS {2}".format(nameserver_suffix, soa_ttl, x) for x in all_server_full_names])
	# Add the address records
	nameserver_tld_content_lines.extend(nameserver_address_records)
	nameserver_tld_contents = "\n".join(nameserver_tld_content_lines) + "\n"
	nameserver_tld_zone_unsigned = "{}.zone.unsigned".format(nameserver_name_suffix_tld)
	nameserver_tld_zone_signed = "{}.zone".format(nameserver_name_suffix_tld)
	nameserver_tld_f = open(nameserver_tld_zone_unsigned, mode="wt")
	nameserver_tld_f.write(nameserver_tld_contents)
	nameserver_tld_f.close()
	log("Wrote out {}".format(nameserver_tld_zone_unsigned))
	this_return_text = subprocess.getoutput("named-checkzone {} {} >/dev/null".format(nameserver_name_suffix_tld, nameserver_tld_zone_unsigned))
	if "fatal" in this_return_text:
		die("Sanity-checking the nameservers TLD zone died with '{}'.".format(this_return_text))
	# Sign the TLD zone
	tld_signing_cmd = "{0}/dnssec-signzone -S -o {1}. -k {2}.key -f {3} {4} >/dev/null 2>/dev/null"\
			.format(binary_prefix, nameserver_name_suffix_tld, nameserver_tld_ksk_file_name, nameserver_tld_zone_signed, nameserver_tld_zone_unsigned)
	this_return_text = subprocess.getoutput(tld_signing_cmd)
	if "fatal" in this_return_text:
		die("Signing the {} zone failed with '{}'.".format(nameserver_tld_zone_unsigned, this_return_text))
	log("Signed the {} zone with '{}'".format(nameserver_name_suffix_tld, tld_signing_cmd))
	# Sanity check the signed zone
	this_return_text = subprocess.getoutput("{}/dnssec-verify -o {}. {} 2>/dev/null"
			.format(binary_prefix, nameserver_name_suffix_tld, nameserver_tld_zone_signed))
	if "fatal" in this_return_text:
		die("Sanity-checking the signed nameserver zone died with '{}'.".format(this_return_text))
	log("Wrote out signed and verified nameserver zone")

	### Make the zone for the nameserver full zone name
	#   Note that this zone is *not* signed; only the TLD zone is
	nameserver_content_lines = []
	# Give it the same SOA as from the root zone
	nameserver_content_lines.append("{0}. {1} IN SOA a.{0}. foo.{0}. {2} 1800 900 604800 {1}".format(nameserver_suffix, soa_ttl, new_soa_value))
	# Add the NS records
	nameserver_content_lines.extend(["{0}. {1} IN NS {2}".format(nameserver_suffix, soa_ttl, x) for x in all_server_full_names])
	# Add the address records
	nameserver_content_lines.extend(nameserver_address_records)
	nameserver_contents = "\n".join(nameserver_content_lines) + "\n"
	nameserver_zone_name = "{}.zone".format(nameserver_suffix)
	nameserver_f = open(nameserver_zone_name, mode="wt")
	nameserver_f.write(nameserver_contents)
	nameserver_f.close()
	log("Wrote out {}".format(nameserver_zone_name))
	this_return_text = subprocess.getoutput("named-checkzone {} {} >/dev/null".format(nameserver_suffix, nameserver_zone_name))
	if "fatal" in this_return_text:
		die("Sanity-checking the server's authoritative zone died with '{}'.".format(this_return_text))

	### Output a file that is the same as the authoritative zone, but formatted like a root hints file
	# Start with the original zone file, remove the SOA, and make the NS records be for the root
	hints_lines = []
	hints_lines.extend([". {} IN NS {}".format(soa_ttl, x) for x in all_server_full_names])
	hints_lines.extend(nameserver_address_records)
	hints_contents = "\n".join(hints_lines) + "\n"
	# Add the address records
	hints_f = open(ROOT_HINTS_FILE_NAME, mode="wt")
	hints_f.write(hints_contents)
	hints_f.close()
	log("Wrote out {}".format(ROOT_HINTS_FILE_NAME))

	### Create the named.conf
	# Make the replacements
	bind_config_contents = '''options {
recursion no;
empty-zones-enable no;
listen-on {LISTEN_ON_IPV4_VALS;};
listen-on-v6 {LISTEN_ON_IPV6_VALS;};
dnssec-enable yes;
allow-transfer { any; };
};
zone "." { type master; file "root.zone"; };
zone "SERVER_ZONE_TLD_GOES_HERE." { type master; file "SERVER_ZONE_TLD_GOES_HERE.zone"; };
zone "SERVER_ZONE_GOES_HERE." { type master; file "SERVER_ZONE_GOES_HERE.zone"; };
'''
	v4_addrs.append("127.0.0.1")
	v6_addrs.append("::1")
	bind_config_contents = bind_config_contents.replace("LISTEN_ON_IPV4_VALS", "; ".join(v4_addrs))
	bind_config_contents = bind_config_contents.replace("LISTEN_ON_IPV6_VALS", "; ".join(v6_addrs))
	bind_config_contents = bind_config_contents.replace("SERVER_ZONE_TLD_GOES_HERE", nameserver_name_suffix_tld)
	bind_config_contents = bind_config_contents.replace("SERVER_ZONE_GOES_HERE", nameserver_suffix)
	bind_conf_f = open("named.conf", mode="wt")
	bind_conf_f.write(bind_config_contents)
	bind_conf_f.close()
	# Sanity check the resulting zone
	this_return_text = subprocess.getoutput("named-checkconf named.conf")
	if "fatal" in this_return_text:
		die("Sanity-checking named.conf died with '{}'.".format(this_return_text))
	log("named.conf is\n{}".format(bind_config_contents))
	log("Wrote out named.conf")

	### Say how to up BIND
	log_and_print("You can start up bind with:\n   cd {} && sudo /path/to/named -c named.conf".format(target_dir))
	log_and_print("The hints file for this setup is at\n   {}/{}".format(target_dir, ROOT_HINTS_FILE_NAME))
	log_and_print("The trust anchor file for this setup is at\n   {}/{}".format(target_dir, TRUST_ANCHOR_DS_FILE_NAME))

	### Write out the BIND include file
	# This contains the trusted-keys statement for the trust anchor
	# Read the KSK as a DNSKEY, then split it into pieces
	for this_line in open("{}.key".format(ksk_for_trust_anchor_file), mode="rt"):
		if this_line.startswith("."):
			ksk_for_signing_dnskey = this_line.strip()
			break
	(dot, _, _, _, flags, protocol, algorithm, pubkey) = ksk_for_signing_dnskey.split(" ", 7)
	bind_lines = []
	bind_lines.append("trusted-keys {{ {0} {1} {2} {3} \"{4}\"; }};".format(dot, flags, protocol, algorithm, pubkey))
	bind_config_contents = "\n".join(bind_lines) + "\n"
	bind_config_f = open(BIND_TRUSTED_KEYS_NAME, mode="wt")
	bind_config_f.write(bind_config_contents)
	bind_config_f.close()
	log("Wrote out {}".format(BIND_TRUSTED_KEYS_NAME))

	### Write out the PowerDNS include file
	# This contains the addDS statement in Lua for the trust anchor
	# Get the DS from TRUST_ANCHOR_DS_FILE_NAME
	the_ds = open(TRUST_ANCHOR_DS_FILE_NAME, mode="rt").read()
	(dot, _, _, keyid, protocol, algorithm, this_hash) = the_ds.split(" ")
	pdns_lines = []
	pdns_lines.append("addDS('.', \"{0} {1} {2} {3}\")".format(keyid, protocol, algorithm, this_hash.strip()))
	pdns_config_contents = "\n".join(pdns_lines) + "\n"
	pdns_config_f = open(PDNS_TRUSTED_KEYS_NAME, mode="wt")
	pdns_config_f.write(pdns_config_contents)
	pdns_config_f.close()
	log("Wrote out {}".format(PDNS_TRUSTED_KEYS_NAME))

	### Finish up
	os.chdir(start_dir)
