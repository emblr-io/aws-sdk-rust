// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListProvisioningArtifactsForServiceActionInput {
    /// <p>The self-service action identifier. For example, <code>act-fs7abcd89wxyz</code>.</p>
    pub service_action_id: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of items to return with this call.</p>
    pub page_size: ::std::option::Option<i32>,
    /// <p>The page token for the next set of results. To retrieve the first set of results, use null.</p>
    pub page_token: ::std::option::Option<::std::string::String>,
    /// <p>The language code.</p>
    /// <ul>
    /// <li>
    /// <p><code>jp</code> - Japanese</p></li>
    /// <li>
    /// <p><code>zh</code> - Chinese</p></li>
    /// </ul>
    pub accept_language: ::std::option::Option<::std::string::String>,
}
impl ListProvisioningArtifactsForServiceActionInput {
    /// <p>The self-service action identifier. For example, <code>act-fs7abcd89wxyz</code>.</p>
    pub fn service_action_id(&self) -> ::std::option::Option<&str> {
        self.service_action_id.as_deref()
    }
    /// <p>The maximum number of items to return with this call.</p>
    pub fn page_size(&self) -> ::std::option::Option<i32> {
        self.page_size
    }
    /// <p>The page token for the next set of results. To retrieve the first set of results, use null.</p>
    pub fn page_token(&self) -> ::std::option::Option<&str> {
        self.page_token.as_deref()
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
}
impl ListProvisioningArtifactsForServiceActionInput {
    /// Creates a new builder-style object to manufacture [`ListProvisioningArtifactsForServiceActionInput`](crate::operation::list_provisioning_artifacts_for_service_action::ListProvisioningArtifactsForServiceActionInput).
    pub fn builder(
    ) -> crate::operation::list_provisioning_artifacts_for_service_action::builders::ListProvisioningArtifactsForServiceActionInputBuilder {
        crate::operation::list_provisioning_artifacts_for_service_action::builders::ListProvisioningArtifactsForServiceActionInputBuilder::default()
    }
}

/// A builder for [`ListProvisioningArtifactsForServiceActionInput`](crate::operation::list_provisioning_artifacts_for_service_action::ListProvisioningArtifactsForServiceActionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListProvisioningArtifactsForServiceActionInputBuilder {
    pub(crate) service_action_id: ::std::option::Option<::std::string::String>,
    pub(crate) page_size: ::std::option::Option<i32>,
    pub(crate) page_token: ::std::option::Option<::std::string::String>,
    pub(crate) accept_language: ::std::option::Option<::std::string::String>,
}
impl ListProvisioningArtifactsForServiceActionInputBuilder {
    /// <p>The self-service action identifier. For example, <code>act-fs7abcd89wxyz</code>.</p>
    /// This field is required.
    pub fn service_action_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_action_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The self-service action identifier. For example, <code>act-fs7abcd89wxyz</code>.</p>
    pub fn set_service_action_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_action_id = input;
        self
    }
    /// <p>The self-service action identifier. For example, <code>act-fs7abcd89wxyz</code>.</p>
    pub fn get_service_action_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_action_id
    }
    /// <p>The maximum number of items to return with this call.</p>
    pub fn page_size(mut self, input: i32) -> Self {
        self.page_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of items to return with this call.</p>
    pub fn set_page_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.page_size = input;
        self
    }
    /// <p>The maximum number of items to return with this call.</p>
    pub fn get_page_size(&self) -> &::std::option::Option<i32> {
        &self.page_size
    }
    /// <p>The page token for the next set of results. To retrieve the first set of results, use null.</p>
    pub fn page_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.page_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The page token for the next set of results. To retrieve the first set of results, use null.</p>
    pub fn set_page_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.page_token = input;
        self
    }
    /// <p>The page token for the next set of results. To retrieve the first set of results, use null.</p>
    pub fn get_page_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.page_token
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
    /// Consumes the builder and constructs a [`ListProvisioningArtifactsForServiceActionInput`](crate::operation::list_provisioning_artifacts_for_service_action::ListProvisioningArtifactsForServiceActionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_provisioning_artifacts_for_service_action::ListProvisioningArtifactsForServiceActionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::list_provisioning_artifacts_for_service_action::ListProvisioningArtifactsForServiceActionInput {
                service_action_id: self.service_action_id,
                page_size: self.page_size,
                page_token: self.page_token,
                accept_language: self.accept_language,
            },
        )
    }
}
