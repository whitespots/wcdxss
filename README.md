# A small contribution to community :)
This is a part of our toolset for [vulneravility monitoring service](https://whitespots.io/vulnerability-monitoring)

### Check other [opensource tools](https://github.com/whitespots/fast-security-scanners)

# Find XSS via Web Cache Deception vulnerability

`docker run --rm -it --name scanner -e VULN_ID=1 -e FIND_XSS=True -e DOMAIN=site.com whitespots/wcdxss`
