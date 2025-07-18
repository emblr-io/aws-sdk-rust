// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Use this structure to propose allowing <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#cryptographic-operations">cryptographic operations</a> in the grant only when the operation request includes the specified <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#encrypt_context">encryption context</a>. You can specify only one type of encryption context. An empty map is treated as not specified. For more information, see <a href="https://docs.aws.amazon.com/kms/latest/APIReference/API_GrantConstraints.html">GrantConstraints</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct KmsGrantConstraints {
    /// <p>A list of key-value pairs that must match the encryption context in the <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#cryptographic-operations">cryptographic operation</a> request. The grant allows the operation only when the encryption context in the request is the same as the encryption context specified in this constraint.</p>
    pub encryption_context_equals: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>A list of key-value pairs that must be included in the encryption context of the <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#cryptographic-operations">cryptographic operation</a> request. The grant allows the cryptographic operation only when the encryption context in the request includes the key-value pairs specified in this constraint, although it can include additional key-value pairs.</p>
    pub encryption_context_subset: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl KmsGrantConstraints {
    /// <p>A list of key-value pairs that must match the encryption context in the <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#cryptographic-operations">cryptographic operation</a> request. The grant allows the operation only when the encryption context in the request is the same as the encryption context specified in this constraint.</p>
    pub fn encryption_context_equals(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.encryption_context_equals.as_ref()
    }
    /// <p>A list of key-value pairs that must be included in the encryption context of the <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#cryptographic-operations">cryptographic operation</a> request. The grant allows the cryptographic operation only when the encryption context in the request includes the key-value pairs specified in this constraint, although it can include additional key-value pairs.</p>
    pub fn encryption_context_subset(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.encryption_context_subset.as_ref()
    }
}
impl KmsGrantConstraints {
    /// Creates a new builder-style object to manufacture [`KmsGrantConstraints`](crate::types::KmsGrantConstraints).
    pub fn builder() -> crate::types::builders::KmsGrantConstraintsBuilder {
        crate::types::builders::KmsGrantConstraintsBuilder::default()
    }
}

/// A builder for [`KmsGrantConstraints`](crate::types::KmsGrantConstraints).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct KmsGrantConstraintsBuilder {
    pub(crate) encryption_context_equals: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) encryption_context_subset: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl KmsGrantConstraintsBuilder {
    /// Adds a key-value pair to `encryption_context_equals`.
    ///
    /// To override the contents of this collection use [`set_encryption_context_equals`](Self::set_encryption_context_equals).
    ///
    /// <p>A list of key-value pairs that must match the encryption context in the <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#cryptographic-operations">cryptographic operation</a> request. The grant allows the operation only when the encryption context in the request is the same as the encryption context specified in this constraint.</p>
    pub fn encryption_context_equals(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.encryption_context_equals.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.encryption_context_equals = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A list of key-value pairs that must match the encryption context in the <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#cryptographic-operations">cryptographic operation</a> request. The grant allows the operation only when the encryption context in the request is the same as the encryption context specified in this constraint.</p>
    pub fn set_encryption_context_equals(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.encryption_context_equals = input;
        self
    }
    /// <p>A list of key-value pairs that must match the encryption context in the <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#cryptographic-operations">cryptographic operation</a> request. The grant allows the operation only when the encryption context in the request is the same as the encryption context specified in this constraint.</p>
    pub fn get_encryption_context_equals(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.encryption_context_equals
    }
    /// Adds a key-value pair to `encryption_context_subset`.
    ///
    /// To override the contents of this collection use [`set_encryption_context_subset`](Self::set_encryption_context_subset).
    ///
    /// <p>A list of key-value pairs that must be included in the encryption context of the <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#cryptographic-operations">cryptographic operation</a> request. The grant allows the cryptographic operation only when the encryption context in the request includes the key-value pairs specified in this constraint, although it can include additional key-value pairs.</p>
    pub fn encryption_context_subset(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.encryption_context_subset.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.encryption_context_subset = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A list of key-value pairs that must be included in the encryption context of the <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#cryptographic-operations">cryptographic operation</a> request. The grant allows the cryptographic operation only when the encryption context in the request includes the key-value pairs specified in this constraint, although it can include additional key-value pairs.</p>
    pub fn set_encryption_context_subset(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.encryption_context_subset = input;
        self
    }
    /// <p>A list of key-value pairs that must be included in the encryption context of the <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#cryptographic-operations">cryptographic operation</a> request. The grant allows the cryptographic operation only when the encryption context in the request includes the key-value pairs specified in this constraint, although it can include additional key-value pairs.</p>
    pub fn get_encryption_context_subset(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.encryption_context_subset
    }
    /// Consumes the builder and constructs a [`KmsGrantConstraints`](crate::types::KmsGrantConstraints).
    pub fn build(self) -> crate::types::KmsGrantConstraints {
        crate::types::KmsGrantConstraints {
            encryption_context_equals: self.encryption_context_equals,
            encryption_context_subset: self.encryption_context_subset,
        }
    }
}
