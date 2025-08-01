// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateRegistryOutput {
    /// <p>The description of the registry.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the registry.</p>
    pub registry_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the registry.</p>
    pub registry_name: ::std::option::Option<::std::string::String>,
    /// <p>Tags associated with the registry.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl UpdateRegistryOutput {
    /// <p>The description of the registry.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The ARN of the registry.</p>
    pub fn registry_arn(&self) -> ::std::option::Option<&str> {
        self.registry_arn.as_deref()
    }
    /// <p>The name of the registry.</p>
    pub fn registry_name(&self) -> ::std::option::Option<&str> {
        self.registry_name.as_deref()
    }
    /// <p>Tags associated with the registry.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateRegistryOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateRegistryOutput {
    /// Creates a new builder-style object to manufacture [`UpdateRegistryOutput`](crate::operation::update_registry::UpdateRegistryOutput).
    pub fn builder() -> crate::operation::update_registry::builders::UpdateRegistryOutputBuilder {
        crate::operation::update_registry::builders::UpdateRegistryOutputBuilder::default()
    }
}

/// A builder for [`UpdateRegistryOutput`](crate::operation::update_registry::UpdateRegistryOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateRegistryOutputBuilder {
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) registry_arn: ::std::option::Option<::std::string::String>,
    pub(crate) registry_name: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl UpdateRegistryOutputBuilder {
    /// <p>The description of the registry.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the registry.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the registry.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The ARN of the registry.</p>
    pub fn registry_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.registry_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the registry.</p>
    pub fn set_registry_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.registry_arn = input;
        self
    }
    /// <p>The ARN of the registry.</p>
    pub fn get_registry_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.registry_arn
    }
    /// <p>The name of the registry.</p>
    pub fn registry_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.registry_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the registry.</p>
    pub fn set_registry_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.registry_name = input;
        self
    }
    /// <p>The name of the registry.</p>
    pub fn get_registry_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.registry_name
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Tags associated with the registry.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Tags associated with the registry.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Tags associated with the registry.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateRegistryOutput`](crate::operation::update_registry::UpdateRegistryOutput).
    pub fn build(self) -> crate::operation::update_registry::UpdateRegistryOutput {
        crate::operation::update_registry::UpdateRegistryOutput {
            description: self.description,
            registry_arn: self.registry_arn,
            registry_name: self.registry_name,
            tags: self.tags,
            _request_id: self._request_id,
        }
    }
}
