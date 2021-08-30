# General

- Use conventional commits https://www.conventionalcommits.org/en/v1.0.0/

- Maintain example **diagrams** for a better understanding of the architecture and sysdig secure resources
  - example diagram-as-code  https://github.com/sysdiglabs/terraform-aws-secure-for-cloud/blob/master/examples/single-account/diagram-single.py
  - resulting diagram https://github.com/sysdiglabs/terraform-aws-secure-for-cloud/blob/master/examples/single-account/diagram-single.png

- Useful Terraform development guides
  - https://www.terraform-best-practices.com



# Pull Request

- Terraform lint and validation is enforced vía  https://pre-commit.com
  - custom configuration at https://github.com/sysdiglabs/terraform-aws-secure-for-cloud/blob/master/.pre-commit-config.yaml
- Testing (WIP)



# Release

- Use semver for releases https://semver.org
- Module official releases will be published at terraform registry
- Just create a tag/release and it will be  fetched by pre-configured webhook and published into.
  - For internal usage, TAGs can be used
  - For officual verions, RELEASEs will be used, with its corresponding changelog description.