// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a provisioning artifact (also known as a version) for a product.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProvisioningArtifactProperties {
    /// <p>The name of the provisioning artifact (for example, v1 v2beta). No spaces are allowed.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the provisioning artifact, including how it differs from the previous provisioning artifact.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Specify the template source with one of the following options, but not both. Keys accepted: \[ LoadTemplateFromURL, ImportFromPhysicalId \]</p>
    /// <p>The URL of the CloudFormation template in Amazon S3 or GitHub in JSON format. Specify the URL in JSON format as follows:</p>
    /// <p><code>"LoadTemplateFromURL": "https://s3.amazonaws.com/cf-templates-ozkq9d3hgiq2-us-east-1/..."</code></p>
    /// <p><code>ImportFromPhysicalId</code>: The physical id of the resource that contains the template. Currently only supports CloudFormation stack arn. Specify the physical id in JSON format as follows: <code>ImportFromPhysicalId: “arn:aws:cloudformation:\[us-east-1\]:\[accountId\]:stack/\[StackName\]/\[resourceId\]</code></p>
    pub info: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The type of provisioning artifact.</p>
    /// <ul>
    /// <li>
    /// <p><code>CLOUD_FORMATION_TEMPLATE</code> - CloudFormation template</p></li>
    /// <li>
    /// <p><code>TERRAFORM_OPEN_SOURCE</code> - Terraform Open Source configuration file</p></li>
    /// <li>
    /// <p><code>TERRAFORM_CLOUD</code> - Terraform Cloud configuration file</p></li>
    /// <li>
    /// <p><code>EXTERNAL</code> - External configuration file</p></li>
    /// </ul>
    pub r#type: ::std::option::Option<crate::types::ProvisioningArtifactType>,
    /// <p>If set to true, Service Catalog stops validating the specified provisioning artifact even if it is invalid.</p>
    /// <p>Service Catalog does not support template validation for the <code>TERRAFORM_OS</code> product type.</p>
    pub disable_template_validation: bool,
}
impl ProvisioningArtifactProperties {
    /// <p>The name of the provisioning artifact (for example, v1 v2beta). No spaces are allowed.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The description of the provisioning artifact, including how it differs from the previous provisioning artifact.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Specify the template source with one of the following options, but not both. Keys accepted: \[ LoadTemplateFromURL, ImportFromPhysicalId \]</p>
    /// <p>The URL of the CloudFormation template in Amazon S3 or GitHub in JSON format. Specify the URL in JSON format as follows:</p>
    /// <p><code>"LoadTemplateFromURL": "https://s3.amazonaws.com/cf-templates-ozkq9d3hgiq2-us-east-1/..."</code></p>
    /// <p><code>ImportFromPhysicalId</code>: The physical id of the resource that contains the template. Currently only supports CloudFormation stack arn. Specify the physical id in JSON format as follows: <code>ImportFromPhysicalId: “arn:aws:cloudformation:\[us-east-1\]:\[accountId\]:stack/\[StackName\]/\[resourceId\]</code></p>
    pub fn info(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.info.as_ref()
    }
    /// <p>The type of provisioning artifact.</p>
    /// <ul>
    /// <li>
    /// <p><code>CLOUD_FORMATION_TEMPLATE</code> - CloudFormation template</p></li>
    /// <li>
    /// <p><code>TERRAFORM_OPEN_SOURCE</code> - Terraform Open Source configuration file</p></li>
    /// <li>
    /// <p><code>TERRAFORM_CLOUD</code> - Terraform Cloud configuration file</p></li>
    /// <li>
    /// <p><code>EXTERNAL</code> - External configuration file</p></li>
    /// </ul>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::ProvisioningArtifactType> {
        self.r#type.as_ref()
    }
    /// <p>If set to true, Service Catalog stops validating the specified provisioning artifact even if it is invalid.</p>
    /// <p>Service Catalog does not support template validation for the <code>TERRAFORM_OS</code> product type.</p>
    pub fn disable_template_validation(&self) -> bool {
        self.disable_template_validation
    }
}
impl ProvisioningArtifactProperties {
    /// Creates a new builder-style object to manufacture [`ProvisioningArtifactProperties`](crate::types::ProvisioningArtifactProperties).
    pub fn builder() -> crate::types::builders::ProvisioningArtifactPropertiesBuilder {
        crate::types::builders::ProvisioningArtifactPropertiesBuilder::default()
    }
}

/// A builder for [`ProvisioningArtifactProperties`](crate::types::ProvisioningArtifactProperties).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProvisioningArtifactPropertiesBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) info: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) r#type: ::std::option::Option<crate::types::ProvisioningArtifactType>,
    pub(crate) disable_template_validation: ::std::option::Option<bool>,
}
impl ProvisioningArtifactPropertiesBuilder {
    /// <p>The name of the provisioning artifact (for example, v1 v2beta). No spaces are allowed.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the provisioning artifact (for example, v1 v2beta). No spaces are allowed.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the provisioning artifact (for example, v1 v2beta). No spaces are allowed.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The description of the provisioning artifact, including how it differs from the previous provisioning artifact.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the provisioning artifact, including how it differs from the previous provisioning artifact.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the provisioning artifact, including how it differs from the previous provisioning artifact.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Adds a key-value pair to `info`.
    ///
    /// To override the contents of this collection use [`set_info`](Self::set_info).
    ///
    /// <p>Specify the template source with one of the following options, but not both. Keys accepted: \[ LoadTemplateFromURL, ImportFromPhysicalId \]</p>
    /// <p>The URL of the CloudFormation template in Amazon S3 or GitHub in JSON format. Specify the URL in JSON format as follows:</p>
    /// <p><code>"LoadTemplateFromURL": "https://s3.amazonaws.com/cf-templates-ozkq9d3hgiq2-us-east-1/..."</code></p>
    /// <p><code>ImportFromPhysicalId</code>: The physical id of the resource that contains the template. Currently only supports CloudFormation stack arn. Specify the physical id in JSON format as follows: <code>ImportFromPhysicalId: “arn:aws:cloudformation:\[us-east-1\]:\[accountId\]:stack/\[StackName\]/\[resourceId\]</code></p>
    pub fn info(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.info.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.info = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Specify the template source with one of the following options, but not both. Keys accepted: \[ LoadTemplateFromURL, ImportFromPhysicalId \]</p>
    /// <p>The URL of the CloudFormation template in Amazon S3 or GitHub in JSON format. Specify the URL in JSON format as follows:</p>
    /// <p><code>"LoadTemplateFromURL": "https://s3.amazonaws.com/cf-templates-ozkq9d3hgiq2-us-east-1/..."</code></p>
    /// <p><code>ImportFromPhysicalId</code>: The physical id of the resource that contains the template. Currently only supports CloudFormation stack arn. Specify the physical id in JSON format as follows: <code>ImportFromPhysicalId: “arn:aws:cloudformation:\[us-east-1\]:\[accountId\]:stack/\[StackName\]/\[resourceId\]</code></p>
    pub fn set_info(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.info = input;
        self
    }
    /// <p>Specify the template source with one of the following options, but not both. Keys accepted: \[ LoadTemplateFromURL, ImportFromPhysicalId \]</p>
    /// <p>The URL of the CloudFormation template in Amazon S3 or GitHub in JSON format. Specify the URL in JSON format as follows:</p>
    /// <p><code>"LoadTemplateFromURL": "https://s3.amazonaws.com/cf-templates-ozkq9d3hgiq2-us-east-1/..."</code></p>
    /// <p><code>ImportFromPhysicalId</code>: The physical id of the resource that contains the template. Currently only supports CloudFormation stack arn. Specify the physical id in JSON format as follows: <code>ImportFromPhysicalId: “arn:aws:cloudformation:\[us-east-1\]:\[accountId\]:stack/\[StackName\]/\[resourceId\]</code></p>
    pub fn get_info(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.info
    }
    /// <p>The type of provisioning artifact.</p>
    /// <ul>
    /// <li>
    /// <p><code>CLOUD_FORMATION_TEMPLATE</code> - CloudFormation template</p></li>
    /// <li>
    /// <p><code>TERRAFORM_OPEN_SOURCE</code> - Terraform Open Source configuration file</p></li>
    /// <li>
    /// <p><code>TERRAFORM_CLOUD</code> - Terraform Cloud configuration file</p></li>
    /// <li>
    /// <p><code>EXTERNAL</code> - External configuration file</p></li>
    /// </ul>
    pub fn r#type(mut self, input: crate::types::ProvisioningArtifactType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of provisioning artifact.</p>
    /// <ul>
    /// <li>
    /// <p><code>CLOUD_FORMATION_TEMPLATE</code> - CloudFormation template</p></li>
    /// <li>
    /// <p><code>TERRAFORM_OPEN_SOURCE</code> - Terraform Open Source configuration file</p></li>
    /// <li>
    /// <p><code>TERRAFORM_CLOUD</code> - Terraform Cloud configuration file</p></li>
    /// <li>
    /// <p><code>EXTERNAL</code> - External configuration file</p></li>
    /// </ul>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::ProvisioningArtifactType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of provisioning artifact.</p>
    /// <ul>
    /// <li>
    /// <p><code>CLOUD_FORMATION_TEMPLATE</code> - CloudFormation template</p></li>
    /// <li>
    /// <p><code>TERRAFORM_OPEN_SOURCE</code> - Terraform Open Source configuration file</p></li>
    /// <li>
    /// <p><code>TERRAFORM_CLOUD</code> - Terraform Cloud configuration file</p></li>
    /// <li>
    /// <p><code>EXTERNAL</code> - External configuration file</p></li>
    /// </ul>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::ProvisioningArtifactType> {
        &self.r#type
    }
    /// <p>If set to true, Service Catalog stops validating the specified provisioning artifact even if it is invalid.</p>
    /// <p>Service Catalog does not support template validation for the <code>TERRAFORM_OS</code> product type.</p>
    pub fn disable_template_validation(mut self, input: bool) -> Self {
        self.disable_template_validation = ::std::option::Option::Some(input);
        self
    }
    /// <p>If set to true, Service Catalog stops validating the specified provisioning artifact even if it is invalid.</p>
    /// <p>Service Catalog does not support template validation for the <code>TERRAFORM_OS</code> product type.</p>
    pub fn set_disable_template_validation(mut self, input: ::std::option::Option<bool>) -> Self {
        self.disable_template_validation = input;
        self
    }
    /// <p>If set to true, Service Catalog stops validating the specified provisioning artifact even if it is invalid.</p>
    /// <p>Service Catalog does not support template validation for the <code>TERRAFORM_OS</code> product type.</p>
    pub fn get_disable_template_validation(&self) -> &::std::option::Option<bool> {
        &self.disable_template_validation
    }
    /// Consumes the builder and constructs a [`ProvisioningArtifactProperties`](crate::types::ProvisioningArtifactProperties).
    pub fn build(self) -> crate::types::ProvisioningArtifactProperties {
        crate::types::ProvisioningArtifactProperties {
            name: self.name,
            description: self.description,
            info: self.info,
            r#type: self.r#type,
            disable_template_validation: self.disable_template_validation.unwrap_or_default(),
        }
    }
}
