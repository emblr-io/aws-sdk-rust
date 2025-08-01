// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CreateIndexInput {
    /// <p>This value helps ensure idempotency. Resource Explorer uses this value to prevent the accidental creation of duplicate versions. We recommend that you generate a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID-type value</a> to ensure the uniqueness of your index.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>The specified tags are attached only to the index created in this Amazon Web Services Region. The tags aren't attached to any of the resources listed in the index.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateIndexInput {
    /// <p>This value helps ensure idempotency. Resource Explorer uses this value to prevent the accidental creation of duplicate versions. We recommend that you generate a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID-type value</a> to ensure the uniqueness of your index.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>The specified tags are attached only to the index created in this Amazon Web Services Region. The tags aren't attached to any of the resources listed in the index.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ::std::fmt::Debug for CreateIndexInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateIndexInput");
        formatter.field("client_token", &self.client_token);
        formatter.field("tags", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl CreateIndexInput {
    /// Creates a new builder-style object to manufacture [`CreateIndexInput`](crate::operation::create_index::CreateIndexInput).
    pub fn builder() -> crate::operation::create_index::builders::CreateIndexInputBuilder {
        crate::operation::create_index::builders::CreateIndexInputBuilder::default()
    }
}

/// A builder for [`CreateIndexInput`](crate::operation::create_index::CreateIndexInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CreateIndexInputBuilder {
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateIndexInputBuilder {
    /// <p>This value helps ensure idempotency. Resource Explorer uses this value to prevent the accidental creation of duplicate versions. We recommend that you generate a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID-type value</a> to ensure the uniqueness of your index.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This value helps ensure idempotency. Resource Explorer uses this value to prevent the accidental creation of duplicate versions. We recommend that you generate a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID-type value</a> to ensure the uniqueness of your index.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>This value helps ensure idempotency. Resource Explorer uses this value to prevent the accidental creation of duplicate versions. We recommend that you generate a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID-type value</a> to ensure the uniqueness of your index.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The specified tags are attached only to the index created in this Amazon Web Services Region. The tags aren't attached to any of the resources listed in the index.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The specified tags are attached only to the index created in this Amazon Web Services Region. The tags aren't attached to any of the resources listed in the index.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The specified tags are attached only to the index created in this Amazon Web Services Region. The tags aren't attached to any of the resources listed in the index.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateIndexInput`](crate::operation::create_index::CreateIndexInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::create_index::CreateIndexInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_index::CreateIndexInput {
            client_token: self.client_token,
            tags: self.tags,
        })
    }
}
impl ::std::fmt::Debug for CreateIndexInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateIndexInputBuilder");
        formatter.field("client_token", &self.client_token);
        formatter.field("tags", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
