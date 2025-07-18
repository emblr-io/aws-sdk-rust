// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CreateEnvironmentInput {
    /// <p>The name of the environment.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the environment.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The network fabric type of the environment.</p>
    pub network_fabric_type: ::std::option::Option<crate::types::NetworkFabricType>,
    /// <p>The tags to assign to the environment. A tag is a label that you assign to an Amazon Web Services resource. Each tag consists of a key-value pair.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl CreateEnvironmentInput {
    /// <p>The name of the environment.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The description of the environment.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The network fabric type of the environment.</p>
    pub fn network_fabric_type(&self) -> ::std::option::Option<&crate::types::NetworkFabricType> {
        self.network_fabric_type.as_ref()
    }
    /// <p>The tags to assign to the environment. A tag is a label that you assign to an Amazon Web Services resource. Each tag consists of a key-value pair.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl ::std::fmt::Debug for CreateEnvironmentInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateEnvironmentInput");
        formatter.field("name", &self.name);
        formatter.field("description", &self.description);
        formatter.field("network_fabric_type", &self.network_fabric_type);
        formatter.field("tags", &"*** Sensitive Data Redacted ***");
        formatter.field("client_token", &self.client_token);
        formatter.finish()
    }
}
impl CreateEnvironmentInput {
    /// Creates a new builder-style object to manufacture [`CreateEnvironmentInput`](crate::operation::create_environment::CreateEnvironmentInput).
    pub fn builder() -> crate::operation::create_environment::builders::CreateEnvironmentInputBuilder {
        crate::operation::create_environment::builders::CreateEnvironmentInputBuilder::default()
    }
}

/// A builder for [`CreateEnvironmentInput`](crate::operation::create_environment::CreateEnvironmentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CreateEnvironmentInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) network_fabric_type: ::std::option::Option<crate::types::NetworkFabricType>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl CreateEnvironmentInputBuilder {
    /// <p>The name of the environment.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the environment.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the environment.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The description of the environment.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the environment.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the environment.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The network fabric type of the environment.</p>
    /// This field is required.
    pub fn network_fabric_type(mut self, input: crate::types::NetworkFabricType) -> Self {
        self.network_fabric_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The network fabric type of the environment.</p>
    pub fn set_network_fabric_type(mut self, input: ::std::option::Option<crate::types::NetworkFabricType>) -> Self {
        self.network_fabric_type = input;
        self
    }
    /// <p>The network fabric type of the environment.</p>
    pub fn get_network_fabric_type(&self) -> &::std::option::Option<crate::types::NetworkFabricType> {
        &self.network_fabric_type
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags to assign to the environment. A tag is a label that you assign to an Amazon Web Services resource. Each tag consists of a key-value pair.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags to assign to the environment. A tag is a label that you assign to an Amazon Web Services resource. Each tag consists of a key-value pair.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags to assign to the environment. A tag is a label that you assign to an Amazon Web Services resource. Each tag consists of a key-value pair.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
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
    /// Consumes the builder and constructs a [`CreateEnvironmentInput`](crate::operation::create_environment::CreateEnvironmentInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_environment::CreateEnvironmentInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_environment::CreateEnvironmentInput {
            name: self.name,
            description: self.description,
            network_fabric_type: self.network_fabric_type,
            tags: self.tags,
            client_token: self.client_token,
        })
    }
}
impl ::std::fmt::Debug for CreateEnvironmentInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateEnvironmentInputBuilder");
        formatter.field("name", &self.name);
        formatter.field("description", &self.description);
        formatter.field("network_fabric_type", &self.network_fabric_type);
        formatter.field("tags", &"*** Sensitive Data Redacted ***");
        formatter.field("client_token", &self.client_token);
        formatter.finish()
    }
}
