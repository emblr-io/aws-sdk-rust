// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CreateAccountAssociationInput {
    /// <p>An idempotency token. If you retry a request that completed successfully initially using the same client token and parameters, then the retry attempt will succeed without performing any further actions.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the connector destination.</p>
    pub connector_destination_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the destination for the new account association.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A description of the account association request.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>A set of key/value pairs that are used to manage the account association.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateAccountAssociationInput {
    /// <p>An idempotency token. If you retry a request that completed successfully initially using the same client token and parameters, then the retry attempt will succeed without performing any further actions.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>The identifier of the connector destination.</p>
    pub fn connector_destination_id(&self) -> ::std::option::Option<&str> {
        self.connector_destination_id.as_deref()
    }
    /// <p>The name of the destination for the new account association.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A description of the account association request.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>A set of key/value pairs that are used to manage the account association.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ::std::fmt::Debug for CreateAccountAssociationInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateAccountAssociationInput");
        formatter.field("client_token", &self.client_token);
        formatter.field("connector_destination_id", &self.connector_destination_id);
        formatter.field("name", &self.name);
        formatter.field("description", &self.description);
        formatter.field("tags", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl CreateAccountAssociationInput {
    /// Creates a new builder-style object to manufacture [`CreateAccountAssociationInput`](crate::operation::create_account_association::CreateAccountAssociationInput).
    pub fn builder() -> crate::operation::create_account_association::builders::CreateAccountAssociationInputBuilder {
        crate::operation::create_account_association::builders::CreateAccountAssociationInputBuilder::default()
    }
}

/// A builder for [`CreateAccountAssociationInput`](crate::operation::create_account_association::CreateAccountAssociationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CreateAccountAssociationInputBuilder {
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) connector_destination_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateAccountAssociationInputBuilder {
    /// <p>An idempotency token. If you retry a request that completed successfully initially using the same client token and parameters, then the retry attempt will succeed without performing any further actions.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An idempotency token. If you retry a request that completed successfully initially using the same client token and parameters, then the retry attempt will succeed without performing any further actions.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>An idempotency token. If you retry a request that completed successfully initially using the same client token and parameters, then the retry attempt will succeed without performing any further actions.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>The identifier of the connector destination.</p>
    /// This field is required.
    pub fn connector_destination_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connector_destination_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the connector destination.</p>
    pub fn set_connector_destination_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connector_destination_id = input;
        self
    }
    /// <p>The identifier of the connector destination.</p>
    pub fn get_connector_destination_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.connector_destination_id
    }
    /// <p>The name of the destination for the new account association.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the destination for the new account association.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the destination for the new account association.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A description of the account association request.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the account association request.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the account association request.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A set of key/value pairs that are used to manage the account association.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A set of key/value pairs that are used to manage the account association.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A set of key/value pairs that are used to manage the account association.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateAccountAssociationInput`](crate::operation::create_account_association::CreateAccountAssociationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_account_association::CreateAccountAssociationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_account_association::CreateAccountAssociationInput {
            client_token: self.client_token,
            connector_destination_id: self.connector_destination_id,
            name: self.name,
            description: self.description,
            tags: self.tags,
        })
    }
}
impl ::std::fmt::Debug for CreateAccountAssociationInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateAccountAssociationInputBuilder");
        formatter.field("client_token", &self.client_token);
        formatter.field("connector_destination_id", &self.connector_destination_id);
        formatter.field("name", &self.name);
        formatter.field("description", &self.description);
        formatter.field("tags", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
