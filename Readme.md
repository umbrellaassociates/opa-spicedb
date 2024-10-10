Open Policy Agent with support for Authzed SpiceDB
---

This plugin adds support for querying and manipulating relations from [Authzed](https://authzed.com/) [SpiceDB](https://github.com/authzed/spicedb) via gRPC as custom builtin commands for [Open Policy Agent](https://www.openpolicyagent.org/).


<br />
<img src="doc/opa-spicedb-demo.gif" alt="topaz model visualization">


## Why use OPA?

[OPA (Open Policy Agent)](https://www.openpolicyagent.org/) decouples policy from code in a highly-performant and elegant way, which makes it perfect for use as an external PDP (Policy Decision Point) for applictions in your stack, implementing a Policy-Based Access Control scheme (PBAC).

## Why use Authzed SpiceDB?

[Authzed SpiceDB](https://authzed.com/spicedb) is an open source authorization system for Relationship-Based Access Control (ReBAC), originally inspired by [Google's Zanzibar paper](https://www.usenix.org/conference/atc19/presentation/pang) and one of the most advanced implementation of it.


## Policy 📃 + Relations 🧠 = 💪 fine-grained access control

PBAC and ReBAC are both strong models for fine-grained access control, while OPA and SpiceDB are award winning solutions and the best-of-breed products for their respective categories.

Combining PBAC and ReBAC results in a flexible and powerful authorizer that can effectively used to protect millions of objects.
<br />


## Supported methods and features

 - SpiceDB gRPC interface available in Rego
 - automatic schema-prefix removal

Currently implemented methods:
 - check_permission
 - lookup_resources
 - lookup_subjects
 - read_relationships
 - write_relationships
 - delete_relationships


### Builtin rego functions for SpiceDB

#### Check permission:

```

spicedb.check_permission("resourceType", "resourceId", "permission", "subjectType", "subjectId")

## result:
{
  "lookedUpAt": "<token>",
  "result": true
}

```

#### Resource lookup

```
spicedb.lookup_resources("resourceType", "permission", "subjectType", "subjectId") 

## result:
{
  "lookedUpAt": "<token>",
  "permission": "<permission>",
  "resourceObjectIds": [
    "<resourceId 1>",
    "<resourceId n>"
  ],
  "resourceObjectType": "<resourceType>",
  "result": true,
  "subjectId": "<subjectId>",
  "subjectType": "<subjectType>"
}

```

#### Subject lookup

```
spicedb.lookup_subjects("<resourceType>", "<resourceId>", "<permission>", "<subjectType>")
## result:
{
  "lookedUpAt": "<token>",
  "permission": "<permission>",
  "resourceObjectId": "<resourceId>",
  "resourceObjectType": "<resourceType>",
  "result": true,
  "subjectIds": [
    "<subjectId 1>",
    "<subjectId n>"
  ],
  "subjectType": "<subjectType>"
}

```

#### Write, touch and delete relationships in a single request

```
write_relations := [
  {"resourceType": "<resourceType>", "resourceId": "<resourceId>", "relationship": "<relationship>", "subjectType": "<subjectType>", "subjectId": "<subjectId>"},
]

touch_relations := []
delete_relations := []

spicedb.write_relationships(write_relations, touch_relations, delete_relations)

## result:
{
  "result": true,
  "writtenAt": "<token>"
}

```

#### Perform read relationships request

```

spicedb.read_relationships("<resourceType>", "<optional-resourceId>", "<optional-permission>", "<optional-subjectType>", "<optional-subjectId>")

## result:
{
  "lookedUpAt": "<token>",
  "result": true,
  "relationships": [
    {
      "relationship": "<relation>",
      "resourceId": "<resourceId>",
      "resourceType": "<resourceType>",
      "subjectId": "<subjectId>",
      "subjectType": "<subjectType>"
    }
  ]
}


```

#### Perform delete relationships request

```
spicedb.delete_relationships("<resourceType>", "<optional-resourceId>", "<optional-permission>", "<optional-subjectType>", "<optional-subjectId>")

## result:
{
  "deletedAt": "<token>",
  "result": true
}

```

# Build 🚀

Make sure you have Go 1.22 installed.

```
make build
```

Or building directly:

```
go build -o opa-spicedb .
```


# Demo ✨

> Start authzed demo environment

```
docker compose -f demo/docker-compose.yaml up -d
```

> Run Open Policy Agent with spicedb plugin enabled


```
./opa-spicedb run \
  --set plugins.spicedb.endpoint=localhost:50051 \
  --set plugins.spicedb.token=foobar \
  --set plugins.spicedb.insecure=true
```

> or use a configuration file

```
./opa-spicedb run -c demo/opa-config-demo.yaml

```


> Query relations against authzed
> See the [example ReBAC schema](./demo/schema-and-data.yaml) for reference.

```
> spicedb.check_permission("document","firstdoc", "view", "user","alice")
{
  "lookedUpAt": "GhUKEzE3MjYwOTIxNjAwMDAwMDAwMDA=",
  "result": true
}

> spicedb.check_permission("document","firstdoc", "edit", "user","bob")
{
  "lookedUpAt": "GhUKEzE3MjY2MTcxMzAwMDAwMDAwMDA=",
  "result": false
}
> exit

```

> Stop demo environment

```
docker compose -f demo/docker-compose.yaml down
```


## 🤝 Contributing

This project is a work in progress.
If something is broken or there's a feature that you want, feel free to check [issues page]() and if so inclined submit a PR!

Contributions, issues and feature requests are welcome.<br />

Here are some general guidelines:<br>

* File an issue first prior to submitting a PR!
* Ensure all exported items are properly commented
* If applicable, submit a test suite against your PR



## Show your support

Please ⭐️ this repository if this project helped you!


## Authors

👤 **Roland Baum**

- Github: [@tr33](https://github.com/tr33)

👤 **umbrella.associates**

- web: [www.umbrella.associates](https://www.umbrella.associates/)


## Credits

- [@thomasdarimont](https://github.com/thomasdarimont/)


## 📝 License

Copyright © 2024 [umbrella.associates](https://github.com/umbrellaassociates).<br />
This project is under [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0) licensed.
