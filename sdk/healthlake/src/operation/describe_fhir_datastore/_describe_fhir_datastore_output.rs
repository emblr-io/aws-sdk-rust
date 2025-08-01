// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeFhirDatastoreOutput {
    /// <p>All properties associated with a data store, including the data store ID, data store ARN, data store name, data store status, when the data store was created, data store type version, and the data store's endpoint.</p>
    pub datastore_properties: ::std::option::Option<crate::types::DatastoreProperties>,
    _request_id: Option<String>,
}
impl DescribeFhirDatastoreOutput {
    /// <p>All properties associated with a data store, including the data store ID, data store ARN, data store name, data store status, when the data store was created, data store type version, and the data store's endpoint.</p>
    pub fn datastore_properties(&self) -> ::std::option::Option<&crate::types::DatastoreProperties> {
        self.datastore_properties.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeFhirDatastoreOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeFhirDatastoreOutput {
    /// Creates a new builder-style object to manufacture [`DescribeFhirDatastoreOutput`](crate::operation::describe_fhir_datastore::DescribeFhirDatastoreOutput).
    pub fn builder() -> crate::operation::describe_fhir_datastore::builders::DescribeFhirDatastoreOutputBuilder {
        crate::operation::describe_fhir_datastore::builders::DescribeFhirDatastoreOutputBuilder::default()
    }
}

/// A builder for [`DescribeFhirDatastoreOutput`](crate::operation::describe_fhir_datastore::DescribeFhirDatastoreOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeFhirDatastoreOutputBuilder {
    pub(crate) datastore_properties: ::std::option::Option<crate::types::DatastoreProperties>,
    _request_id: Option<String>,
}
impl DescribeFhirDatastoreOutputBuilder {
    /// <p>All properties associated with a data store, including the data store ID, data store ARN, data store name, data store status, when the data store was created, data store type version, and the data store's endpoint.</p>
    /// This field is required.
    pub fn datastore_properties(mut self, input: crate::types::DatastoreProperties) -> Self {
        self.datastore_properties = ::std::option::Option::Some(input);
        self
    }
    /// <p>All properties associated with a data store, including the data store ID, data store ARN, data store name, data store status, when the data store was created, data store type version, and the data store's endpoint.</p>
    pub fn set_datastore_properties(mut self, input: ::std::option::Option<crate::types::DatastoreProperties>) -> Self {
        self.datastore_properties = input;
        self
    }
    /// <p>All properties associated with a data store, including the data store ID, data store ARN, data store name, data store status, when the data store was created, data store type version, and the data store's endpoint.</p>
    pub fn get_datastore_properties(&self) -> &::std::option::Option<crate::types::DatastoreProperties> {
        &self.datastore_properties
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeFhirDatastoreOutput`](crate::operation::describe_fhir_datastore::DescribeFhirDatastoreOutput).
    pub fn build(self) -> crate::operation::describe_fhir_datastore::DescribeFhirDatastoreOutput {
        crate::operation::describe_fhir_datastore::DescribeFhirDatastoreOutput {
            datastore_properties: self.datastore_properties,
            _request_id: self._request_id,
        }
    }
}
