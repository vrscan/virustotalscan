# virustotalscan
Provides better virustotal.com support to scan and research files and binaries.


---

To use library just register email and get the key!

Example:
```
	client, err := Register("your_registered@email.here")

	found, err := client.Check(filebuf)

	if found { some alert }
```