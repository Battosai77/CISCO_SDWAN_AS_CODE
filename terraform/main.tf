module "sdwan" {
  source  = "netascode/nac-sdwan/sdwan"     # Module YAML→vManage (Netascode)
  version = "1.3.0"                         # ✅ Compatible 20.x

  yaml_files = [                            # Liste exhaustive des YAML IaC
    "${path.module}/yaml/site1.yml",
    # "yaml/site2.yml",                    # + sites futurs
  ]
}
