.PHONY: test local scan-example

test:
	python -m unittest discover -s tests -v

local:
	python -m dnsmasq_safety_checker local

scan-example:
	python -m dnsmasq_safety_checker scan 192.168.1.0/24 --poc
