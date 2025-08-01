// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateWorldTemplateInput {
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    pub client_request_token: ::std::option::Option<::std::string::String>,
    /// <p>The name of the world template.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The world template body.</p>
    pub template_body: ::std::option::Option<::std::string::String>,
    /// <p>The location of the world template.</p>
    pub template_location: ::std::option::Option<crate::types::TemplateLocation>,
    /// <p>A map that contains tag keys and tag values that are attached to the world template.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateWorldTemplateInput {
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
    /// <p>The name of the world template.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The world template body.</p>
    pub fn template_body(&self) -> ::std::option::Option<&str> {
        self.template_body.as_deref()
    }
    /// <p>The location of the world template.</p>
    pub fn template_location(&self) -> ::std::option::Option<&crate::types::TemplateLocation> {
        self.template_location.as_ref()
    }
    /// <p>A map that contains tag keys and tag values that are attached to the world template.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl CreateWorldTemplateInput {
    /// Creates a new builder-style object to manufacture [`CreateWorldTemplateInput`](crate::operation::create_world_template::CreateWorldTemplateInput).
    pub fn builder() -> crate::operation::create_world_template::builders::CreateWorldTemplateInputBuilder {
        crate::operation::create_world_template::builders::CreateWorldTemplateInputBuilder::default()
    }
}

/// A builder for [`CreateWorldTemplateInput`](crate::operation::create_world_template::CreateWorldTemplateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateWorldTemplateInputBuilder {
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) template_body: ::std::option::Option<::std::string::String>,
    pub(crate) template_location: ::std::option::Option<crate::types::TemplateLocation>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateWorldTemplateInputBuilder {
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    pub fn client_request_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_request_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    pub fn set_client_request_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_request_token = input;
        self
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    pub fn get_client_request_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_request_token
    }
    /// <p>The name of the world template.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the world template.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the world template.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The world template body.</p>
    pub fn template_body(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_body = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The world template body.</p>
    pub fn set_template_body(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_body = input;
        self
    }
    /// <p>The world template body.</p>
    pub fn get_template_body(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_body
    }
    /// <p>The location of the world template.</p>
    pub fn template_location(mut self, input: crate::types::TemplateLocation) -> Self {
        self.template_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>The location of the world template.</p>
    pub fn set_template_location(mut self, input: ::std::option::Option<crate::types::TemplateLocation>) -> Self {
        self.template_location = input;
        self
    }
    /// <p>The location of the world template.</p>
    pub fn get_template_location(&self) -> &::std::option::Option<crate::types::TemplateLocation> {
        &self.template_location
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A map that contains tag keys and tag values that are attached to the world template.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A map that contains tag keys and tag values that are attached to the world template.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A map that contains tag keys and tag values that are attached to the world template.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateWorldTemplateInput`](crate::operation::create_world_template::CreateWorldTemplateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_world_template::CreateWorldTemplateInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_world_template::CreateWorldTemplateInput {
            client_request_token: self.client_request_token,
            name: self.name,
            template_body: self.template_body,
            template_location: self.template_location,
            tags: self.tags,
        })
    }
}
