// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateReviewTemplateInput {
    /// <p>Name of the review template.</p>
    pub template_name: ::std::option::Option<::std::string::String>,
    /// <p>The review template description.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Lenses applied to the review template.</p>
    pub lenses: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The notes associated with the workload.</p>
    /// <p>For a review template, these are the notes that will be associated with the workload when the template is applied.</p>
    pub notes: ::std::option::Option<::std::string::String>,
    /// <p>The tags assigned to the review template.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>A unique case-sensitive string used to ensure that this request is idempotent (executes only once).</p>
    /// <p>You should not reuse the same token for other requests. If you retry a request with the same client request token and the same parameters after the original request has completed successfully, the result of the original request is returned.</p><important>
    /// <p>This token is listed as required, however, if you do not specify it, the Amazon Web Services SDKs automatically generate one for you. If you are not using the Amazon Web Services SDK or the CLI, you must provide this token or the request will fail.</p>
    /// </important>
    pub client_request_token: ::std::option::Option<::std::string::String>,
}
impl CreateReviewTemplateInput {
    /// <p>Name of the review template.</p>
    pub fn template_name(&self) -> ::std::option::Option<&str> {
        self.template_name.as_deref()
    }
    /// <p>The review template description.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Lenses applied to the review template.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.lenses.is_none()`.
    pub fn lenses(&self) -> &[::std::string::String] {
        self.lenses.as_deref().unwrap_or_default()
    }
    /// <p>The notes associated with the workload.</p>
    /// <p>For a review template, these are the notes that will be associated with the workload when the template is applied.</p>
    pub fn notes(&self) -> ::std::option::Option<&str> {
        self.notes.as_deref()
    }
    /// <p>The tags assigned to the review template.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>A unique case-sensitive string used to ensure that this request is idempotent (executes only once).</p>
    /// <p>You should not reuse the same token for other requests. If you retry a request with the same client request token and the same parameters after the original request has completed successfully, the result of the original request is returned.</p><important>
    /// <p>This token is listed as required, however, if you do not specify it, the Amazon Web Services SDKs automatically generate one for you. If you are not using the Amazon Web Services SDK or the CLI, you must provide this token or the request will fail.</p>
    /// </important>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
}
impl CreateReviewTemplateInput {
    /// Creates a new builder-style object to manufacture [`CreateReviewTemplateInput`](crate::operation::create_review_template::CreateReviewTemplateInput).
    pub fn builder() -> crate::operation::create_review_template::builders::CreateReviewTemplateInputBuilder {
        crate::operation::create_review_template::builders::CreateReviewTemplateInputBuilder::default()
    }
}

/// A builder for [`CreateReviewTemplateInput`](crate::operation::create_review_template::CreateReviewTemplateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateReviewTemplateInputBuilder {
    pub(crate) template_name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) lenses: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) notes: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
}
impl CreateReviewTemplateInputBuilder {
    /// <p>Name of the review template.</p>
    /// This field is required.
    pub fn template_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the review template.</p>
    pub fn set_template_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_name = input;
        self
    }
    /// <p>Name of the review template.</p>
    pub fn get_template_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_name
    }
    /// <p>The review template description.</p>
    /// This field is required.
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The review template description.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The review template description.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `lenses`.
    ///
    /// To override the contents of this collection use [`set_lenses`](Self::set_lenses).
    ///
    /// <p>Lenses applied to the review template.</p>
    pub fn lenses(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.lenses.unwrap_or_default();
        v.push(input.into());
        self.lenses = ::std::option::Option::Some(v);
        self
    }
    /// <p>Lenses applied to the review template.</p>
    pub fn set_lenses(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.lenses = input;
        self
    }
    /// <p>Lenses applied to the review template.</p>
    pub fn get_lenses(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.lenses
    }
    /// <p>The notes associated with the workload.</p>
    /// <p>For a review template, these are the notes that will be associated with the workload when the template is applied.</p>
    pub fn notes(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.notes = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The notes associated with the workload.</p>
    /// <p>For a review template, these are the notes that will be associated with the workload when the template is applied.</p>
    pub fn set_notes(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.notes = input;
        self
    }
    /// <p>The notes associated with the workload.</p>
    /// <p>For a review template, these are the notes that will be associated with the workload when the template is applied.</p>
    pub fn get_notes(&self) -> &::std::option::Option<::std::string::String> {
        &self.notes
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags assigned to the review template.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags assigned to the review template.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags assigned to the review template.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>A unique case-sensitive string used to ensure that this request is idempotent (executes only once).</p>
    /// <p>You should not reuse the same token for other requests. If you retry a request with the same client request token and the same parameters after the original request has completed successfully, the result of the original request is returned.</p><important>
    /// <p>This token is listed as required, however, if you do not specify it, the Amazon Web Services SDKs automatically generate one for you. If you are not using the Amazon Web Services SDK or the CLI, you must provide this token or the request will fail.</p>
    /// </important>
    /// This field is required.
    pub fn client_request_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_request_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique case-sensitive string used to ensure that this request is idempotent (executes only once).</p>
    /// <p>You should not reuse the same token for other requests. If you retry a request with the same client request token and the same parameters after the original request has completed successfully, the result of the original request is returned.</p><important>
    /// <p>This token is listed as required, however, if you do not specify it, the Amazon Web Services SDKs automatically generate one for you. If you are not using the Amazon Web Services SDK or the CLI, you must provide this token or the request will fail.</p>
    /// </important>
    pub fn set_client_request_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_request_token = input;
        self
    }
    /// <p>A unique case-sensitive string used to ensure that this request is idempotent (executes only once).</p>
    /// <p>You should not reuse the same token for other requests. If you retry a request with the same client request token and the same parameters after the original request has completed successfully, the result of the original request is returned.</p><important>
    /// <p>This token is listed as required, however, if you do not specify it, the Amazon Web Services SDKs automatically generate one for you. If you are not using the Amazon Web Services SDK or the CLI, you must provide this token or the request will fail.</p>
    /// </important>
    pub fn get_client_request_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_request_token
    }
    /// Consumes the builder and constructs a [`CreateReviewTemplateInput`](crate::operation::create_review_template::CreateReviewTemplateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_review_template::CreateReviewTemplateInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_review_template::CreateReviewTemplateInput {
            template_name: self.template_name,
            description: self.description,
            lenses: self.lenses,
            notes: self.notes,
            tags: self.tags,
            client_request_token: self.client_request_token,
        })
    }
}
