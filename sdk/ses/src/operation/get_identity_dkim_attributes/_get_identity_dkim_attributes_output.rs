// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the status of Amazon SES Easy DKIM signing for an identity. For domain identities, this response also contains the DKIM tokens that are required for Easy DKIM signing, and whether Amazon SES successfully verified that these tokens were published.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetIdentityDkimAttributesOutput {
    /// <p>The DKIM attributes for an email address or a domain.</p>
    pub dkim_attributes: ::std::collections::HashMap<::std::string::String, crate::types::IdentityDkimAttributes>,
    _request_id: Option<String>,
}
impl GetIdentityDkimAttributesOutput {
    /// <p>The DKIM attributes for an email address or a domain.</p>
    pub fn dkim_attributes(&self) -> &::std::collections::HashMap<::std::string::String, crate::types::IdentityDkimAttributes> {
        &self.dkim_attributes
    }
}
impl ::aws_types::request_id::RequestId for GetIdentityDkimAttributesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetIdentityDkimAttributesOutput {
    /// Creates a new builder-style object to manufacture [`GetIdentityDkimAttributesOutput`](crate::operation::get_identity_dkim_attributes::GetIdentityDkimAttributesOutput).
    pub fn builder() -> crate::operation::get_identity_dkim_attributes::builders::GetIdentityDkimAttributesOutputBuilder {
        crate::operation::get_identity_dkim_attributes::builders::GetIdentityDkimAttributesOutputBuilder::default()
    }
}

/// A builder for [`GetIdentityDkimAttributesOutput`](crate::operation::get_identity_dkim_attributes::GetIdentityDkimAttributesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetIdentityDkimAttributesOutputBuilder {
    pub(crate) dkim_attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::IdentityDkimAttributes>>,
    _request_id: Option<String>,
}
impl GetIdentityDkimAttributesOutputBuilder {
    /// Adds a key-value pair to `dkim_attributes`.
    ///
    /// To override the contents of this collection use [`set_dkim_attributes`](Self::set_dkim_attributes).
    ///
    /// <p>The DKIM attributes for an email address or a domain.</p>
    pub fn dkim_attributes(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::IdentityDkimAttributes) -> Self {
        let mut hash_map = self.dkim_attributes.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.dkim_attributes = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The DKIM attributes for an email address or a domain.</p>
    pub fn set_dkim_attributes(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::IdentityDkimAttributes>>,
    ) -> Self {
        self.dkim_attributes = input;
        self
    }
    /// <p>The DKIM attributes for an email address or a domain.</p>
    pub fn get_dkim_attributes(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::IdentityDkimAttributes>> {
        &self.dkim_attributes
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetIdentityDkimAttributesOutput`](crate::operation::get_identity_dkim_attributes::GetIdentityDkimAttributesOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`dkim_attributes`](crate::operation::get_identity_dkim_attributes::builders::GetIdentityDkimAttributesOutputBuilder::dkim_attributes)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_identity_dkim_attributes::GetIdentityDkimAttributesOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_identity_dkim_attributes::GetIdentityDkimAttributesOutput {
            dkim_attributes: self.dkim_attributes.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "dkim_attributes",
                    "dkim_attributes was not specified but it is required when building GetIdentityDkimAttributesOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
