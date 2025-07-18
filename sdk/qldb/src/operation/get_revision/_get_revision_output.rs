// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct GetRevisionOutput {
    /// <p>The proof object in Amazon Ion format returned by a <code>GetRevision</code> request. A proof contains the list of hash values that are required to recalculate the specified digest using a Merkle tree, starting with the specified document revision.</p>
    pub proof: ::std::option::Option<crate::types::ValueHolder>,
    /// <p>The document revision data object in Amazon Ion format.</p>
    pub revision: ::std::option::Option<crate::types::ValueHolder>,
    _request_id: Option<String>,
}
impl GetRevisionOutput {
    /// <p>The proof object in Amazon Ion format returned by a <code>GetRevision</code> request. A proof contains the list of hash values that are required to recalculate the specified digest using a Merkle tree, starting with the specified document revision.</p>
    pub fn proof(&self) -> ::std::option::Option<&crate::types::ValueHolder> {
        self.proof.as_ref()
    }
    /// <p>The document revision data object in Amazon Ion format.</p>
    pub fn revision(&self) -> ::std::option::Option<&crate::types::ValueHolder> {
        self.revision.as_ref()
    }
}
impl ::std::fmt::Debug for GetRevisionOutput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("GetRevisionOutput");
        formatter.field("proof", &"*** Sensitive Data Redacted ***");
        formatter.field("revision", &"*** Sensitive Data Redacted ***");
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
impl ::aws_types::request_id::RequestId for GetRevisionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetRevisionOutput {
    /// Creates a new builder-style object to manufacture [`GetRevisionOutput`](crate::operation::get_revision::GetRevisionOutput).
    pub fn builder() -> crate::operation::get_revision::builders::GetRevisionOutputBuilder {
        crate::operation::get_revision::builders::GetRevisionOutputBuilder::default()
    }
}

/// A builder for [`GetRevisionOutput`](crate::operation::get_revision::GetRevisionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct GetRevisionOutputBuilder {
    pub(crate) proof: ::std::option::Option<crate::types::ValueHolder>,
    pub(crate) revision: ::std::option::Option<crate::types::ValueHolder>,
    _request_id: Option<String>,
}
impl GetRevisionOutputBuilder {
    /// <p>The proof object in Amazon Ion format returned by a <code>GetRevision</code> request. A proof contains the list of hash values that are required to recalculate the specified digest using a Merkle tree, starting with the specified document revision.</p>
    pub fn proof(mut self, input: crate::types::ValueHolder) -> Self {
        self.proof = ::std::option::Option::Some(input);
        self
    }
    /// <p>The proof object in Amazon Ion format returned by a <code>GetRevision</code> request. A proof contains the list of hash values that are required to recalculate the specified digest using a Merkle tree, starting with the specified document revision.</p>
    pub fn set_proof(mut self, input: ::std::option::Option<crate::types::ValueHolder>) -> Self {
        self.proof = input;
        self
    }
    /// <p>The proof object in Amazon Ion format returned by a <code>GetRevision</code> request. A proof contains the list of hash values that are required to recalculate the specified digest using a Merkle tree, starting with the specified document revision.</p>
    pub fn get_proof(&self) -> &::std::option::Option<crate::types::ValueHolder> {
        &self.proof
    }
    /// <p>The document revision data object in Amazon Ion format.</p>
    /// This field is required.
    pub fn revision(mut self, input: crate::types::ValueHolder) -> Self {
        self.revision = ::std::option::Option::Some(input);
        self
    }
    /// <p>The document revision data object in Amazon Ion format.</p>
    pub fn set_revision(mut self, input: ::std::option::Option<crate::types::ValueHolder>) -> Self {
        self.revision = input;
        self
    }
    /// <p>The document revision data object in Amazon Ion format.</p>
    pub fn get_revision(&self) -> &::std::option::Option<crate::types::ValueHolder> {
        &self.revision
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetRevisionOutput`](crate::operation::get_revision::GetRevisionOutput).
    pub fn build(self) -> crate::operation::get_revision::GetRevisionOutput {
        crate::operation::get_revision::GetRevisionOutput {
            proof: self.proof,
            revision: self.revision,
            _request_id: self._request_id,
        }
    }
}
impl ::std::fmt::Debug for GetRevisionOutputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("GetRevisionOutputBuilder");
        formatter.field("proof", &"*** Sensitive Data Redacted ***");
        formatter.field("revision", &"*** Sensitive Data Redacted ***");
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
