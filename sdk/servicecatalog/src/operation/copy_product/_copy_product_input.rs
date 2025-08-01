// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CopyProductInput {
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub accept_language: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the source product.</p>
    pub source_product_arn: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the target product. By default, a new product is created.</p>
    pub target_product_id: ::std::option::Option<::std::string::String>,
    /// <p>A name for the target product. The default is the name of the source product.</p>
    pub target_product_name: ::std::option::Option<::std::string::String>,
    /// <p>The identifiers of the provisioning artifacts (also known as versions) of the product to copy. By default, all provisioning artifacts are copied.</p>
    pub source_provisioning_artifact_identifiers:
        ::std::option::Option<::std::vec::Vec<::std::collections::HashMap<crate::types::ProvisioningArtifactPropertyName, ::std::string::String>>>,
    /// <p>The copy options. If the value is <code>CopyTags</code>, the tags from the source product are copied to the target product.</p>
    pub copy_options: ::std::option::Option<::std::vec::Vec<crate::types::CopyOption>>,
    /// <p>A unique identifier that you provide to ensure idempotency. If multiple requests differ only by the idempotency token, the same response is returned for each repeated request.</p>
    pub idempotency_token: ::std::option::Option<::std::string::String>,
}
impl CopyProductInput {
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
    /// <p>The Amazon Resource Name (ARN) of the source product.</p>
    pub fn source_product_arn(&self) -> ::std::option::Option<&str> {
        self.source_product_arn.as_deref()
    }
    /// <p>The identifier of the target product. By default, a new product is created.</p>
    pub fn target_product_id(&self) -> ::std::option::Option<&str> {
        self.target_product_id.as_deref()
    }
    /// <p>A name for the target product. The default is the name of the source product.</p>
    pub fn target_product_name(&self) -> ::std::option::Option<&str> {
        self.target_product_name.as_deref()
    }
    /// <p>The identifiers of the provisioning artifacts (also known as versions) of the product to copy. By default, all provisioning artifacts are copied.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.source_provisioning_artifact_identifiers.is_none()`.
    pub fn source_provisioning_artifact_identifiers(
        &self,
    ) -> &[::std::collections::HashMap<crate::types::ProvisioningArtifactPropertyName, ::std::string::String>] {
        self.source_provisioning_artifact_identifiers.as_deref().unwrap_or_default()
    }
    /// <p>The copy options. If the value is <code>CopyTags</code>, the tags from the source product are copied to the target product.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.copy_options.is_none()`.
    pub fn copy_options(&self) -> &[crate::types::CopyOption] {
        self.copy_options.as_deref().unwrap_or_default()
    }
    /// <p>A unique identifier that you provide to ensure idempotency. If multiple requests differ only by the idempotency token, the same response is returned for each repeated request.</p>
    pub fn idempotency_token(&self) -> ::std::option::Option<&str> {
        self.idempotency_token.as_deref()
    }
}
impl CopyProductInput {
    /// Creates a new builder-style object to manufacture [`CopyProductInput`](crate::operation::copy_product::CopyProductInput).
    pub fn builder() -> crate::operation::copy_product::builders::CopyProductInputBuilder {
        crate::operation::copy_product::builders::CopyProductInputBuilder::default()
    }
}

/// A builder for [`CopyProductInput`](crate::operation::copy_product::CopyProductInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CopyProductInputBuilder {
    pub(crate) accept_language: ::std::option::Option<::std::string::String>,
    pub(crate) source_product_arn: ::std::option::Option<::std::string::String>,
    pub(crate) target_product_id: ::std::option::Option<::std::string::String>,
    pub(crate) target_product_name: ::std::option::Option<::std::string::String>,
    pub(crate) source_provisioning_artifact_identifiers:
        ::std::option::Option<::std::vec::Vec<::std::collections::HashMap<crate::types::ProvisioningArtifactPropertyName, ::std::string::String>>>,
    pub(crate) copy_options: ::std::option::Option<::std::vec::Vec<crate::types::CopyOption>>,
    pub(crate) idempotency_token: ::std::option::Option<::std::string::String>,
}
impl CopyProductInputBuilder {
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
    /// <p>The Amazon Resource Name (ARN) of the source product.</p>
    /// This field is required.
    pub fn source_product_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_product_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the source product.</p>
    pub fn set_source_product_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_product_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the source product.</p>
    pub fn get_source_product_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_product_arn
    }
    /// <p>The identifier of the target product. By default, a new product is created.</p>
    pub fn target_product_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_product_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the target product. By default, a new product is created.</p>
    pub fn set_target_product_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_product_id = input;
        self
    }
    /// <p>The identifier of the target product. By default, a new product is created.</p>
    pub fn get_target_product_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_product_id
    }
    /// <p>A name for the target product. The default is the name of the source product.</p>
    pub fn target_product_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_product_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A name for the target product. The default is the name of the source product.</p>
    pub fn set_target_product_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_product_name = input;
        self
    }
    /// <p>A name for the target product. The default is the name of the source product.</p>
    pub fn get_target_product_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_product_name
    }
    /// Appends an item to `source_provisioning_artifact_identifiers`.
    ///
    /// To override the contents of this collection use [`set_source_provisioning_artifact_identifiers`](Self::set_source_provisioning_artifact_identifiers).
    ///
    /// <p>The identifiers of the provisioning artifacts (also known as versions) of the product to copy. By default, all provisioning artifacts are copied.</p>
    pub fn source_provisioning_artifact_identifiers(
        mut self,
        input: ::std::collections::HashMap<crate::types::ProvisioningArtifactPropertyName, ::std::string::String>,
    ) -> Self {
        let mut v = self.source_provisioning_artifact_identifiers.unwrap_or_default();
        v.push(input);
        self.source_provisioning_artifact_identifiers = ::std::option::Option::Some(v);
        self
    }
    /// <p>The identifiers of the provisioning artifacts (also known as versions) of the product to copy. By default, all provisioning artifacts are copied.</p>
    pub fn set_source_provisioning_artifact_identifiers(
        mut self,
        input: ::std::option::Option<
            ::std::vec::Vec<::std::collections::HashMap<crate::types::ProvisioningArtifactPropertyName, ::std::string::String>>,
        >,
    ) -> Self {
        self.source_provisioning_artifact_identifiers = input;
        self
    }
    /// <p>The identifiers of the provisioning artifacts (also known as versions) of the product to copy. By default, all provisioning artifacts are copied.</p>
    pub fn get_source_provisioning_artifact_identifiers(
        &self,
    ) -> &::std::option::Option<::std::vec::Vec<::std::collections::HashMap<crate::types::ProvisioningArtifactPropertyName, ::std::string::String>>>
    {
        &self.source_provisioning_artifact_identifiers
    }
    /// Appends an item to `copy_options`.
    ///
    /// To override the contents of this collection use [`set_copy_options`](Self::set_copy_options).
    ///
    /// <p>The copy options. If the value is <code>CopyTags</code>, the tags from the source product are copied to the target product.</p>
    pub fn copy_options(mut self, input: crate::types::CopyOption) -> Self {
        let mut v = self.copy_options.unwrap_or_default();
        v.push(input);
        self.copy_options = ::std::option::Option::Some(v);
        self
    }
    /// <p>The copy options. If the value is <code>CopyTags</code>, the tags from the source product are copied to the target product.</p>
    pub fn set_copy_options(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CopyOption>>) -> Self {
        self.copy_options = input;
        self
    }
    /// <p>The copy options. If the value is <code>CopyTags</code>, the tags from the source product are copied to the target product.</p>
    pub fn get_copy_options(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CopyOption>> {
        &self.copy_options
    }
    /// <p>A unique identifier that you provide to ensure idempotency. If multiple requests differ only by the idempotency token, the same response is returned for each repeated request.</p>
    /// This field is required.
    pub fn idempotency_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.idempotency_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier that you provide to ensure idempotency. If multiple requests differ only by the idempotency token, the same response is returned for each repeated request.</p>
    pub fn set_idempotency_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.idempotency_token = input;
        self
    }
    /// <p>A unique identifier that you provide to ensure idempotency. If multiple requests differ only by the idempotency token, the same response is returned for each repeated request.</p>
    pub fn get_idempotency_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.idempotency_token
    }
    /// Consumes the builder and constructs a [`CopyProductInput`](crate::operation::copy_product::CopyProductInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::copy_product::CopyProductInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::copy_product::CopyProductInput {
            accept_language: self.accept_language,
            source_product_arn: self.source_product_arn,
            target_product_id: self.target_product_id,
            target_product_name: self.target_product_name,
            source_provisioning_artifact_identifiers: self.source_provisioning_artifact_identifiers,
            copy_options: self.copy_options,
            idempotency_token: self.idempotency_token,
        })
    }
}
