# nsm

```sh
nsm provider list
nsm provider add
nsm provider use
nsm provider remove

nsm projects
nsm secrets
nsm secret-value <name>
```

## configure a provider

### passbolt

```sh
nsm provider add my-passbolt passbolt --server https://passbolt.domain.com --private_key_file /path/to/private.key
org_folder=$(passbolt create folder --name "organization name")
nsm provider add my-passbolt passbolt --server https://passbolt.domain.com --private_key_file /path/to/private.key --organization_root_folder $org_folder
```

### use the provider

```sh
nsm provider use provider-name
```

### manage secrets

```sh
# creates a new folder in the $org_folder (or in the organization_root_folder specified during the provider setup)
nsm project create --name "$(pwd)" --folder $org_folder
# adds the content file .env as a resource into the specified folder
nsm project secret add .env
# retrieve the latest version of the secrets in this project
nsm project secret restore
# remove all the secrets in the current folder
nsm project secret clean
```

## prerequisites

### passbolt

- [passbolt-cli](https://github.com/passbolt/go-passbolt-cli)
