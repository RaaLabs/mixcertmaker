# mixcertmaker

To generate certificates used with Clear Linux mixer / swupd

The functions in this code is the same functions found in the [mixer-tools](https://github.com/clearlinux/mixer-tools) but contains only the parts needed to make the certificates. In the original mixer-tools the self signed certificate created is hard coded to only be valid for 1 year. This package let's you create certificates with the same naming standard where the default is 100 years, but can set to a custom value.

## Flags

```bash
  -years int
        number of years that the certificate will be valid (default 100)
```
