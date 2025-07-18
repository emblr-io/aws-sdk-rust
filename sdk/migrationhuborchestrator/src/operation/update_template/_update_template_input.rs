// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateTemplateInput {
    /// <p>The ID of the request to update a migration workflow template.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the migration workflow template to update.</p>
    pub template_name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the migration workflow template to update.</p>
    pub template_description: ::std::option::Option<::std::string::String>,
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl UpdateTemplateInput {
    /// <p>The ID of the request to update a migration workflow template.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The name of the migration workflow template to update.</p>
    pub fn template_name(&self) -> ::std::option::Option<&str> {
        self.template_name.as_deref()
    }
    /// <p>The description of the migration workflow template to update.</p>
    pub fn template_description(&self) -> ::std::option::Option<&str> {
        self.template_description.as_deref()
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl UpdateTemplateInput {
    /// Creates a new builder-style object to manufacture [`UpdateTemplateInput`](crate::operation::update_template::UpdateTemplateInput).
    pub fn builder() -> crate::operation::update_template::builders::UpdateTemplateInputBuilder {
        crate::operation::update_template::builders::UpdateTemplateInputBuilder::default()
    }
}

/// A builder for [`UpdateTemplateInput`](crate::operation::update_template::UpdateTemplateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateTemplateInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) template_name: ::std::option::Option<::std::string::String>,
    pub(crate) template_description: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl UpdateTemplateInputBuilder {
    /// <p>The ID of the request to update a migration workflow template.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the request to update a migration workflow template.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the request to update a migration workflow template.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The name of the migration workflow template to update.</p>
    pub fn template_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the migration workflow template to update.</p>
    pub fn set_template_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_name = input;
        self
    }
    /// <p>The name of the migration workflow template to update.</p>
    pub fn get_template_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_name
    }
    /// <p>The description of the migration workflow template to update.</p>
    pub fn template_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the migration workflow template to update.</p>
    pub fn set_template_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_description = input;
        self
    }
    /// <p>The description of the migration workflow template to update.</p>
    pub fn get_template_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_description
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`UpdateTemplateInput`](crate::operation::update_template::UpdateTemplateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_template::UpdateTemplateInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_template::UpdateTemplateInput {
            id: self.id,
            template_name: self.template_name,
            template_description: self.template_description,
            client_token: self.client_token,
        })
    }
}
