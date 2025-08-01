// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetObjectInformationOutput {
    /// <p>The facets attached to the specified object. Although the response does not include minor version information, the most recently applied minor version of each Facet is in effect. See <code>GetAppliedSchemaVersion</code> for details.</p>
    pub schema_facets: ::std::option::Option<::std::vec::Vec<crate::types::SchemaFacet>>,
    /// <p>The <code>ObjectIdentifier</code> of the specified object.</p>
    pub object_identifier: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetObjectInformationOutput {
    /// <p>The facets attached to the specified object. Although the response does not include minor version information, the most recently applied minor version of each Facet is in effect. See <code>GetAppliedSchemaVersion</code> for details.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.schema_facets.is_none()`.
    pub fn schema_facets(&self) -> &[crate::types::SchemaFacet] {
        self.schema_facets.as_deref().unwrap_or_default()
    }
    /// <p>The <code>ObjectIdentifier</code> of the specified object.</p>
    pub fn object_identifier(&self) -> ::std::option::Option<&str> {
        self.object_identifier.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetObjectInformationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetObjectInformationOutput {
    /// Creates a new builder-style object to manufacture [`GetObjectInformationOutput`](crate::operation::get_object_information::GetObjectInformationOutput).
    pub fn builder() -> crate::operation::get_object_information::builders::GetObjectInformationOutputBuilder {
        crate::operation::get_object_information::builders::GetObjectInformationOutputBuilder::default()
    }
}

/// A builder for [`GetObjectInformationOutput`](crate::operation::get_object_information::GetObjectInformationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetObjectInformationOutputBuilder {
    pub(crate) schema_facets: ::std::option::Option<::std::vec::Vec<crate::types::SchemaFacet>>,
    pub(crate) object_identifier: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetObjectInformationOutputBuilder {
    /// Appends an item to `schema_facets`.
    ///
    /// To override the contents of this collection use [`set_schema_facets`](Self::set_schema_facets).
    ///
    /// <p>The facets attached to the specified object. Although the response does not include minor version information, the most recently applied minor version of each Facet is in effect. See <code>GetAppliedSchemaVersion</code> for details.</p>
    pub fn schema_facets(mut self, input: crate::types::SchemaFacet) -> Self {
        let mut v = self.schema_facets.unwrap_or_default();
        v.push(input);
        self.schema_facets = ::std::option::Option::Some(v);
        self
    }
    /// <p>The facets attached to the specified object. Although the response does not include minor version information, the most recently applied minor version of each Facet is in effect. See <code>GetAppliedSchemaVersion</code> for details.</p>
    pub fn set_schema_facets(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SchemaFacet>>) -> Self {
        self.schema_facets = input;
        self
    }
    /// <p>The facets attached to the specified object. Although the response does not include minor version information, the most recently applied minor version of each Facet is in effect. See <code>GetAppliedSchemaVersion</code> for details.</p>
    pub fn get_schema_facets(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SchemaFacet>> {
        &self.schema_facets
    }
    /// <p>The <code>ObjectIdentifier</code> of the specified object.</p>
    pub fn object_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.object_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>ObjectIdentifier</code> of the specified object.</p>
    pub fn set_object_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.object_identifier = input;
        self
    }
    /// <p>The <code>ObjectIdentifier</code> of the specified object.</p>
    pub fn get_object_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.object_identifier
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetObjectInformationOutput`](crate::operation::get_object_information::GetObjectInformationOutput).
    pub fn build(self) -> crate::operation::get_object_information::GetObjectInformationOutput {
        crate::operation::get_object_information::GetObjectInformationOutput {
            schema_facets: self.schema_facets,
            object_identifier: self.object_identifier,
            _request_id: self._request_id,
        }
    }
}
