// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeProvisioningParametersInput {
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub accept_language: ::std::option::Option<::std::string::String>,
    /// <p>The product identifier. You must provide the product name or ID, but not both.</p>
    pub product_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the product. You must provide the name or ID, but not both.</p>
    pub product_name: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the provisioning artifact. You must provide the name or ID, but not both.</p>
    pub provisioning_artifact_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the provisioning artifact. You must provide the name or ID, but not both.</p>
    pub provisioning_artifact_name: ::std::option::Option<::std::string::String>,
    /// <p>The path identifier of the product. This value is optional if the product has a default path, and required if the product has more than one path. To list the paths for a product, use <code>ListLaunchPaths</code>. You must provide the name or ID, but not both.</p>
    pub path_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the path. You must provide the name or ID, but not both.</p>
    pub path_name: ::std::option::Option<::std::string::String>,
}
impl DescribeProvisioningParametersInput {
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub fn accept_language(&self) -> ::std::option::Option<&str> {
        self.accept_language.as_deref()
    }
    /// <p>The product identifier. You must provide the product name or ID, but not both.</p>
    pub fn product_id(&self) -> ::std::option::Option<&str> {
        self.product_id.as_deref()
    }
    /// <p>The name of the product. You must provide the name or ID, but not both.</p>
    pub fn product_name(&self) -> ::std::option::Option<&str> {
        self.product_name.as_deref()
    }
    /// <p>The identifier of the provisioning artifact. You must provide the name or ID, but not both.</p>
    pub fn provisioning_artifact_id(&self) -> ::std::option::Option<&str> {
        self.provisioning_artifact_id.as_deref()
    }
    /// <p>The name of the provisioning artifact. You must provide the name or ID, but not both.</p>
    pub fn provisioning_artifact_name(&self) -> ::std::option::Option<&str> {
        self.provisioning_artifact_name.as_deref()
    }
    /// <p>The path identifier of the product. This value is optional if the product has a default path, and required if the product has more than one path. To list the paths for a product, use <code>ListLaunchPaths</code>. You must provide the name or ID, but not both.</p>
    pub fn path_id(&self) -> ::std::option::Option<&str> {
        self.path_id.as_deref()
    }
    /// <p>The name of the path. You must provide the name or ID, but not both.</p>
    pub fn path_name(&self) -> ::std::option::Option<&str> {
        self.path_name.as_deref()
    }
}
impl DescribeProvisioningParametersInput {
    /// Creates a new builder-style object to manufacture [`DescribeProvisioningParametersInput`](crate::operation::describe_provisioning_parameters::DescribeProvisioningParametersInput).
    pub fn builder() -> crate::operation::describe_provisioning_parameters::builders::DescribeProvisioningParametersInputBuilder {
        crate::operation::describe_provisioning_parameters::builders::DescribeProvisioningParametersInputBuilder::default()
    }
}

/// A builder for [`DescribeProvisioningParametersInput`](crate::operation::describe_provisioning_parameters::DescribeProvisioningParametersInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeProvisioningParametersInputBuilder {
    pub(crate) accept_language: ::std::option::Option<::std::string::String>,
    pub(crate) product_id: ::std::option::Option<::std::string::String>,
    pub(crate) product_name: ::std::option::Option<::std::string::String>,
    pub(crate) provisioning_artifact_id: ::std::option::Option<::std::string::String>,
    pub(crate) provisioning_artifact_name: ::std::option::Option<::std::string::String>,
    pub(crate) path_id: ::std::option::Option<::std::string::String>,
    pub(crate) path_name: ::std::option::Option<::std::string::String>,
}
impl DescribeProvisioningParametersInputBuilder {
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub fn accept_language(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.accept_language = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub fn set_accept_language(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.accept_language = input;
        self
    }
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub fn get_accept_language(&self) -> &::std::option::Option<::std::string::String> {
        &self.accept_language
    }
    /// <p>The product identifier. You must provide the product name or ID, but not both.</p>
    pub fn product_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.product_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The product identifier. You must provide the product name or ID, but not both.</p>
    pub fn set_product_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.product_id = input;
        self
    }
    /// <p>The product identifier. You must provide the product name or ID, but not both.</p>
    pub fn get_product_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.product_id
    }
    /// <p>The name of the product. You must provide the name or ID, but not both.</p>
    pub fn product_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.product_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the product. You must provide the name or ID, but not both.</p>
    pub fn set_product_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.product_name = input;
        self
    }
    /// <p>The name of the product. You must provide the name or ID, but not both.</p>
    pub fn get_product_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.product_name
    }
    /// <p>The identifier of the provisioning artifact. You must provide the name or ID, but not both.</p>
    pub fn provisioning_artifact_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.provisioning_artifact_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the provisioning artifact. You must provide the name or ID, but not both.</p>
    pub fn set_provisioning_artifact_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.provisioning_artifact_id = input;
        self
    }
    /// <p>The identifier of the provisioning artifact. You must provide the name or ID, but not both.</p>
    pub fn get_provisioning_artifact_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.provisioning_artifact_id
    }
    /// <p>The name of the provisioning artifact. You must provide the name or ID, but not both.</p>
    pub fn provisioning_artifact_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.provisioning_artifact_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the provisioning artifact. You must provide the name or ID, but not both.</p>
    pub fn set_provisioning_artifact_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.provisioning_artifact_name = input;
        self
    }
    /// <p>The name of the provisioning artifact. You must provide the name or ID, but not both.</p>
    pub fn get_provisioning_artifact_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.provisioning_artifact_name
    }
    /// <p>The path identifier of the product. This value is optional if the product has a default path, and required if the product has more than one path. To list the paths for a product, use <code>ListLaunchPaths</code>. You must provide the name or ID, but not both.</p>
    pub fn path_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.path_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path identifier of the product. This value is optional if the product has a default path, and required if the product has more than one path. To list the paths for a product, use <code>ListLaunchPaths</code>. You must provide the name or ID, but not both.</p>
    pub fn set_path_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.path_id = input;
        self
    }
    /// <p>The path identifier of the product. This value is optional if the product has a default path, and required if the product has more than one path. To list the paths for a product, use <code>ListLaunchPaths</code>. You must provide the name or ID, but not both.</p>
    pub fn get_path_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.path_id
    }
    /// <p>The name of the path. You must provide the name or ID, but not both.</p>
    pub fn path_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.path_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the path. You must provide the name or ID, but not both.</p>
    pub fn set_path_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.path_name = input;
        self
    }
    /// <p>The name of the path. You must provide the name or ID, but not both.</p>
    pub fn get_path_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.path_name
    }
    /// Consumes the builder and constructs a [`DescribeProvisioningParametersInput`](crate::operation::describe_provisioning_parameters::DescribeProvisioningParametersInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_provisioning_parameters::DescribeProvisioningParametersInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_provisioning_parameters::DescribeProvisioningParametersInput {
            accept_language: self.accept_language,
            product_id: self.product_id,
            product_name: self.product_name,
            provisioning_artifact_id: self.provisioning_artifact_id,
            provisioning_artifact_name: self.provisioning_artifact_name,
            path_id: self.path_id,
            path_name: self.path_name,
        })
    }
}
