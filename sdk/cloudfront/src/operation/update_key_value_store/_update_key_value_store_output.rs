// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateKeyValueStoreOutput {
    /// <p>The resulting key value store to update.</p>
    pub key_value_store: ::std::option::Option<crate::types::KeyValueStore>,
    /// <p>The <code>ETag</code> of the resulting key value store.</p>
    pub e_tag: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateKeyValueStoreOutput {
    /// <p>The resulting key value store to update.</p>
    pub fn key_value_store(&self) -> ::std::option::Option<&crate::types::KeyValueStore> {
        self.key_value_store.as_ref()
    }
    /// <p>The <code>ETag</code> of the resulting key value store.</p>
    pub fn e_tag(&self) -> ::std::option::Option<&str> {
        self.e_tag.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateKeyValueStoreOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateKeyValueStoreOutput {
    /// Creates a new builder-style object to manufacture [`UpdateKeyValueStoreOutput`](crate::operation::update_key_value_store::UpdateKeyValueStoreOutput).
    pub fn builder() -> crate::operation::update_key_value_store::builders::UpdateKeyValueStoreOutputBuilder {
        crate::operation::update_key_value_store::builders::UpdateKeyValueStoreOutputBuilder::default()
    }
}

/// A builder for [`UpdateKeyValueStoreOutput`](crate::operation::update_key_value_store::UpdateKeyValueStoreOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateKeyValueStoreOutputBuilder {
    pub(crate) key_value_store: ::std::option::Option<crate::types::KeyValueStore>,
    pub(crate) e_tag: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateKeyValueStoreOutputBuilder {
    /// <p>The resulting key value store to update.</p>
    pub fn key_value_store(mut self, input: crate::types::KeyValueStore) -> Self {
        self.key_value_store = ::std::option::Option::Some(input);
        self
    }
    /// <p>The resulting key value store to update.</p>
    pub fn set_key_value_store(mut self, input: ::std::option::Option<crate::types::KeyValueStore>) -> Self {
        self.key_value_store = input;
        self
    }
    /// <p>The resulting key value store to update.</p>
    pub fn get_key_value_store(&self) -> &::std::option::Option<crate::types::KeyValueStore> {
        &self.key_value_store
    }
    /// <p>The <code>ETag</code> of the resulting key value store.</p>
    pub fn e_tag(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.e_tag = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>ETag</code> of the resulting key value store.</p>
    pub fn set_e_tag(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.e_tag = input;
        self
    }
    /// <p>The <code>ETag</code> of the resulting key value store.</p>
    pub fn get_e_tag(&self) -> &::std::option::Option<::std::string::String> {
        &self.e_tag
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateKeyValueStoreOutput`](crate::operation::update_key_value_store::UpdateKeyValueStoreOutput).
    pub fn build(self) -> crate::operation::update_key_value_store::UpdateKeyValueStoreOutput {
        crate::operation::update_key_value_store::UpdateKeyValueStoreOutput {
            key_value_store: self.key_value_store,
            e_tag: self.e_tag,
            _request_id: self._request_id,
        }
    }
}
