// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TerminateProvisionedProductInput {
    /// <p>The name of the provisioned product. You cannot specify both <code>ProvisionedProductName</code> and <code>ProvisionedProductId</code>.</p>
    pub provisioned_product_name: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the provisioned product. You cannot specify both <code>ProvisionedProductName</code> and <code>ProvisionedProductId</code>.</p>
    pub provisioned_product_id: ::std::option::Option<::std::string::String>,
    /// <p>An idempotency token that uniquely identifies the termination request. This token is only valid during the termination process. After the provisioned product is terminated, subsequent requests to terminate the same provisioned product always return <b>ResourceNotFound</b>.</p>
    pub terminate_token: ::std::option::Option<::std::string::String>,
    /// <p>If set to true, Service Catalog stops managing the specified provisioned product even if it cannot delete the underlying resources.</p>
    pub ignore_errors: ::std::option::Option<bool>,
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub accept_language: ::std::option::Option<::std::string::String>,
    /// <p>When this boolean parameter is set to true, the <code>TerminateProvisionedProduct</code> API deletes the Service Catalog provisioned product. However, it does not remove the CloudFormation stack, stack set, or the underlying resources of the deleted provisioned product. The default value is false.</p>
    pub retain_physical_resources: ::std::option::Option<bool>,
}
impl TerminateProvisionedProductInput {
    /// <p>The name of the provisioned product. You cannot specify both <code>ProvisionedProductName</code> and <code>ProvisionedProductId</code>.</p>
    pub fn provisioned_product_name(&self) -> ::std::option::Option<&str> {
        self.provisioned_product_name.as_deref()
    }
    /// <p>The identifier of the provisioned product. You cannot specify both <code>ProvisionedProductName</code> and <code>ProvisionedProductId</code>.</p>
    pub fn provisioned_product_id(&self) -> ::std::option::Option<&str> {
        self.provisioned_product_id.as_deref()
    }
    /// <p>An idempotency token that uniquely identifies the termination request. This token is only valid during the termination process. After the provisioned product is terminated, subsequent requests to terminate the same provisioned product always return <b>ResourceNotFound</b>.</p>
    pub fn terminate_token(&self) -> ::std::option::Option<&str> {
        self.terminate_token.as_deref()
    }
    /// <p>If set to true, Service Catalog stops managing the specified provisioned product even if it cannot delete the underlying resources.</p>
    pub fn ignore_errors(&self) -> ::std::option::Option<bool> {
        self.ignore_errors
    }
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
    /// <p>When this boolean parameter is set to true, the <code>TerminateProvisionedProduct</code> API deletes the Service Catalog provisioned product. However, it does not remove the CloudFormation stack, stack set, or the underlying resources of the deleted provisioned product. The default value is false.</p>
    pub fn retain_physical_resources(&self) -> ::std::option::Option<bool> {
        self.retain_physical_resources
    }
}
impl TerminateProvisionedProductInput {
    /// Creates a new builder-style object to manufacture [`TerminateProvisionedProductInput`](crate::operation::terminate_provisioned_product::TerminateProvisionedProductInput).
    pub fn builder() -> crate::operation::terminate_provisioned_product::builders::TerminateProvisionedProductInputBuilder {
        crate::operation::terminate_provisioned_product::builders::TerminateProvisionedProductInputBuilder::default()
    }
}

/// A builder for [`TerminateProvisionedProductInput`](crate::operation::terminate_provisioned_product::TerminateProvisionedProductInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TerminateProvisionedProductInputBuilder {
    pub(crate) provisioned_product_name: ::std::option::Option<::std::string::String>,
    pub(crate) provisioned_product_id: ::std::option::Option<::std::string::String>,
    pub(crate) terminate_token: ::std::option::Option<::std::string::String>,
    pub(crate) ignore_errors: ::std::option::Option<bool>,
    pub(crate) accept_language: ::std::option::Option<::std::string::String>,
    pub(crate) retain_physical_resources: ::std::option::Option<bool>,
}
impl TerminateProvisionedProductInputBuilder {
    /// <p>The name of the provisioned product. You cannot specify both <code>ProvisionedProductName</code> and <code>ProvisionedProductId</code>.</p>
    pub fn provisioned_product_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.provisioned_product_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the provisioned product. You cannot specify both <code>ProvisionedProductName</code> and <code>ProvisionedProductId</code>.</p>
    pub fn set_provisioned_product_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.provisioned_product_name = input;
        self
    }
    /// <p>The name of the provisioned product. You cannot specify both <code>ProvisionedProductName</code> and <code>ProvisionedProductId</code>.</p>
    pub fn get_provisioned_product_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.provisioned_product_name
    }
    /// <p>The identifier of the provisioned product. You cannot specify both <code>ProvisionedProductName</code> and <code>ProvisionedProductId</code>.</p>
    pub fn provisioned_product_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.provisioned_product_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the provisioned product. You cannot specify both <code>ProvisionedProductName</code> and <code>ProvisionedProductId</code>.</p>
    pub fn set_provisioned_product_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.provisioned_product_id = input;
        self
    }
    /// <p>The identifier of the provisioned product. You cannot specify both <code>ProvisionedProductName</code> and <code>ProvisionedProductId</code>.</p>
    pub fn get_provisioned_product_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.provisioned_product_id
    }
    /// <p>An idempotency token that uniquely identifies the termination request. This token is only valid during the termination process. After the provisioned product is terminated, subsequent requests to terminate the same provisioned product always return <b>ResourceNotFound</b>.</p>
    /// This field is required.
    pub fn terminate_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.terminate_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An idempotency token that uniquely identifies the termination request. This token is only valid during the termination process. After the provisioned product is terminated, subsequent requests to terminate the same provisioned product always return <b>ResourceNotFound</b>.</p>
    pub fn set_terminate_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.terminate_token = input;
        self
    }
    /// <p>An idempotency token that uniquely identifies the termination request. This token is only valid during the termination process. After the provisioned product is terminated, subsequent requests to terminate the same provisioned product always return <b>ResourceNotFound</b>.</p>
    pub fn get_terminate_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.terminate_token
    }
    /// <p>If set to true, Service Catalog stops managing the specified provisioned product even if it cannot delete the underlying resources.</p>
    pub fn ignore_errors(mut self, input: bool) -> Self {
        self.ignore_errors = ::std::option::Option::Some(input);
        self
    }
    /// <p>If set to true, Service Catalog stops managing the specified provisioned product even if it cannot delete the underlying resources.</p>
    pub fn set_ignore_errors(mut self, input: ::std::option::Option<bool>) -> Self {
        self.ignore_errors = input;
        self
    }
    /// <p>If set to true, Service Catalog stops managing the specified provisioned product even if it cannot delete the underlying resources.</p>
    pub fn get_ignore_errors(&self) -> &::std::option::Option<bool> {
        &self.ignore_errors
    }
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
    /// <p>When this boolean parameter is set to true, the <code>TerminateProvisionedProduct</code> API deletes the Service Catalog provisioned product. However, it does not remove the CloudFormation stack, stack set, or the underlying resources of the deleted provisioned product. The default value is false.</p>
    pub fn retain_physical_resources(mut self, input: bool) -> Self {
        self.retain_physical_resources = ::std::option::Option::Some(input);
        self
    }
    /// <p>When this boolean parameter is set to true, the <code>TerminateProvisionedProduct</code> API deletes the Service Catalog provisioned product. However, it does not remove the CloudFormation stack, stack set, or the underlying resources of the deleted provisioned product. The default value is false.</p>
    pub fn set_retain_physical_resources(mut self, input: ::std::option::Option<bool>) -> Self {
        self.retain_physical_resources = input;
        self
    }
    /// <p>When this boolean parameter is set to true, the <code>TerminateProvisionedProduct</code> API deletes the Service Catalog provisioned product. However, it does not remove the CloudFormation stack, stack set, or the underlying resources of the deleted provisioned product. The default value is false.</p>
    pub fn get_retain_physical_resources(&self) -> &::std::option::Option<bool> {
        &self.retain_physical_resources
    }
    /// Consumes the builder and constructs a [`TerminateProvisionedProductInput`](crate::operation::terminate_provisioned_product::TerminateProvisionedProductInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::terminate_provisioned_product::TerminateProvisionedProductInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::terminate_provisioned_product::TerminateProvisionedProductInput {
            provisioned_product_name: self.provisioned_product_name,
            provisioned_product_id: self.provisioned_product_id,
            terminate_token: self.terminate_token,
            ignore_errors: self.ignore_errors,
            accept_language: self.accept_language,
            retain_physical_resources: self.retain_physical_resources,
        })
    }
}
