// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the ARN's of a SageMaker AI image and SageMaker AI image version, and the instance type that the version runs on.</p><note>
/// <p>When both <code>SageMakerImageVersionArn</code> and <code>SageMakerImageArn</code> are passed, <code>SageMakerImageVersionArn</code> is used. Any updates to <code>SageMakerImageArn</code> will not take effect if <code>SageMakerImageVersionArn</code> already exists in the <code>ResourceSpec</code> because <code>SageMakerImageVersionArn</code> always takes precedence. To clear the value set for <code>SageMakerImageVersionArn</code>, pass <code>None</code> as the value.</p>
/// </note>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResourceSpec {
    /// <p>The ARN of the SageMaker AI image that the image version belongs to.</p>
    pub sage_maker_image_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the image version created on the instance. To clear the value set for <code>SageMakerImageVersionArn</code>, pass <code>None</code> as the value.</p>
    pub sage_maker_image_version_arn: ::std::option::Option<::std::string::String>,
    /// <p>The SageMakerImageVersionAlias of the image to launch with. This value is in SemVer 2.0.0 versioning format.</p>
    pub sage_maker_image_version_alias: ::std::option::Option<::std::string::String>,
    /// <p>The instance type that the image version runs on.</p><note>
    /// <p><b>JupyterServer apps</b> only support the <code>system</code> value.</p>
    /// <p>For <b>KernelGateway apps</b>, the <code>system</code> value is translated to <code>ml.t3.medium</code>. KernelGateway apps also support all other values for available instance types.</p>
    /// </note>
    pub instance_type: ::std::option::Option<crate::types::AppInstanceType>,
    /// <p>The Amazon Resource Name (ARN) of the Lifecycle Configuration attached to the Resource.</p>
    pub lifecycle_config_arn: ::std::option::Option<::std::string::String>,
}
impl ResourceSpec {
    /// <p>The ARN of the SageMaker AI image that the image version belongs to.</p>
    pub fn sage_maker_image_arn(&self) -> ::std::option::Option<&str> {
        self.sage_maker_image_arn.as_deref()
    }
    /// <p>The ARN of the image version created on the instance. To clear the value set for <code>SageMakerImageVersionArn</code>, pass <code>None</code> as the value.</p>
    pub fn sage_maker_image_version_arn(&self) -> ::std::option::Option<&str> {
        self.sage_maker_image_version_arn.as_deref()
    }
    /// <p>The SageMakerImageVersionAlias of the image to launch with. This value is in SemVer 2.0.0 versioning format.</p>
    pub fn sage_maker_image_version_alias(&self) -> ::std::option::Option<&str> {
        self.sage_maker_image_version_alias.as_deref()
    }
    /// <p>The instance type that the image version runs on.</p><note>
    /// <p><b>JupyterServer apps</b> only support the <code>system</code> value.</p>
    /// <p>For <b>KernelGateway apps</b>, the <code>system</code> value is translated to <code>ml.t3.medium</code>. KernelGateway apps also support all other values for available instance types.</p>
    /// </note>
    pub fn instance_type(&self) -> ::std::option::Option<&crate::types::AppInstanceType> {
        self.instance_type.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the Lifecycle Configuration attached to the Resource.</p>
    pub fn lifecycle_config_arn(&self) -> ::std::option::Option<&str> {
        self.lifecycle_config_arn.as_deref()
    }
}
impl ResourceSpec {
    /// Creates a new builder-style object to manufacture [`ResourceSpec`](crate::types::ResourceSpec).
    pub fn builder() -> crate::types::builders::ResourceSpecBuilder {
        crate::types::builders::ResourceSpecBuilder::default()
    }
}

/// A builder for [`ResourceSpec`](crate::types::ResourceSpec).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResourceSpecBuilder {
    pub(crate) sage_maker_image_arn: ::std::option::Option<::std::string::String>,
    pub(crate) sage_maker_image_version_arn: ::std::option::Option<::std::string::String>,
    pub(crate) sage_maker_image_version_alias: ::std::option::Option<::std::string::String>,
    pub(crate) instance_type: ::std::option::Option<crate::types::AppInstanceType>,
    pub(crate) lifecycle_config_arn: ::std::option::Option<::std::string::String>,
}
impl ResourceSpecBuilder {
    /// <p>The ARN of the SageMaker AI image that the image version belongs to.</p>
    pub fn sage_maker_image_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sage_maker_image_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the SageMaker AI image that the image version belongs to.</p>
    pub fn set_sage_maker_image_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sage_maker_image_arn = input;
        self
    }
    /// <p>The ARN of the SageMaker AI image that the image version belongs to.</p>
    pub fn get_sage_maker_image_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.sage_maker_image_arn
    }
    /// <p>The ARN of the image version created on the instance. To clear the value set for <code>SageMakerImageVersionArn</code>, pass <code>None</code> as the value.</p>
    pub fn sage_maker_image_version_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sage_maker_image_version_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the image version created on the instance. To clear the value set for <code>SageMakerImageVersionArn</code>, pass <code>None</code> as the value.</p>
    pub fn set_sage_maker_image_version_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sage_maker_image_version_arn = input;
        self
    }
    /// <p>The ARN of the image version created on the instance. To clear the value set for <code>SageMakerImageVersionArn</code>, pass <code>None</code> as the value.</p>
    pub fn get_sage_maker_image_version_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.sage_maker_image_version_arn
    }
    /// <p>The SageMakerImageVersionAlias of the image to launch with. This value is in SemVer 2.0.0 versioning format.</p>
    pub fn sage_maker_image_version_alias(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sage_maker_image_version_alias = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The SageMakerImageVersionAlias of the image to launch with. This value is in SemVer 2.0.0 versioning format.</p>
    pub fn set_sage_maker_image_version_alias(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sage_maker_image_version_alias = input;
        self
    }
    /// <p>The SageMakerImageVersionAlias of the image to launch with. This value is in SemVer 2.0.0 versioning format.</p>
    pub fn get_sage_maker_image_version_alias(&self) -> &::std::option::Option<::std::string::String> {
        &self.sage_maker_image_version_alias
    }
    /// <p>The instance type that the image version runs on.</p><note>
    /// <p><b>JupyterServer apps</b> only support the <code>system</code> value.</p>
    /// <p>For <b>KernelGateway apps</b>, the <code>system</code> value is translated to <code>ml.t3.medium</code>. KernelGateway apps also support all other values for available instance types.</p>
    /// </note>
    pub fn instance_type(mut self, input: crate::types::AppInstanceType) -> Self {
        self.instance_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The instance type that the image version runs on.</p><note>
    /// <p><b>JupyterServer apps</b> only support the <code>system</code> value.</p>
    /// <p>For <b>KernelGateway apps</b>, the <code>system</code> value is translated to <code>ml.t3.medium</code>. KernelGateway apps also support all other values for available instance types.</p>
    /// </note>
    pub fn set_instance_type(mut self, input: ::std::option::Option<crate::types::AppInstanceType>) -> Self {
        self.instance_type = input;
        self
    }
    /// <p>The instance type that the image version runs on.</p><note>
    /// <p><b>JupyterServer apps</b> only support the <code>system</code> value.</p>
    /// <p>For <b>KernelGateway apps</b>, the <code>system</code> value is translated to <code>ml.t3.medium</code>. KernelGateway apps also support all other values for available instance types.</p>
    /// </note>
    pub fn get_instance_type(&self) -> &::std::option::Option<crate::types::AppInstanceType> {
        &self.instance_type
    }
    /// <p>The Amazon Resource Name (ARN) of the Lifecycle Configuration attached to the Resource.</p>
    pub fn lifecycle_config_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.lifecycle_config_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Lifecycle Configuration attached to the Resource.</p>
    pub fn set_lifecycle_config_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.lifecycle_config_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Lifecycle Configuration attached to the Resource.</p>
    pub fn get_lifecycle_config_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.lifecycle_config_arn
    }
    /// Consumes the builder and constructs a [`ResourceSpec`](crate::types::ResourceSpec).
    pub fn build(self) -> crate::types::ResourceSpec {
        crate::types::ResourceSpec {
            sage_maker_image_arn: self.sage_maker_image_arn,
            sage_maker_image_version_arn: self.sage_maker_image_version_arn,
            sage_maker_image_version_alias: self.sage_maker_image_version_alias,
            instance_type: self.instance_type,
            lifecycle_config_arn: self.lifecycle_config_arn,
        }
    }
}
