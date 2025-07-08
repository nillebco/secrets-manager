# nsm

```sh
nsm provider list
nsm provider add
nsm provider use
nsm provider remove

nsm organizations
nsm projects
nsm secrets
nsm secret-value <name>
```

```sh
nsm provider add my-passbolt passbolt --server https://safe.tail961085.ts.net --private_key_file /path/to/private.key --organization_root_folder 72447f98-436c-47e4-aff9-f2061f0812a8
nsm project create --name "passbolt-server" --folder $org_folder
nsm project secret add .env
nsm project secret restore
nsm project secret clean
```
