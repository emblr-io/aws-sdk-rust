// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateDataLakeOutput {
    /// <p>The created Security Lake configuration object.</p>
    pub data_lakes: ::std::option::Option<::std::vec::Vec<crate::types::DataLakeResource>>,
    _request_id: Option<String>,
}
impl CreateDataLakeOutput {
    /// <p>The created Security Lake configuration object.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.data_lakes.is_none()`.
    pub fn data_lakes(&self) -> &[crate::types::DataLakeResource] {
        self.data_lakes.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for CreateDataLakeOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateDataLakeOutput {
    /// Creates a new builder-style object to manufacture [`CreateDataLakeOutput`](crate::operation::create_data_lake::CreateDataLakeOutput).
    pub fn builder() -> crate::operation::create_data_lake::builders::CreateDataLakeOutputBuilder {
        crate::operation::create_data_lake::builders::CreateDataLakeOutputBuilder::default()
    }
}

/// A builder for [`CreateDataLakeOutput`](crate::operation::create_data_lake::CreateDataLakeOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateDataLakeOutputBuilder {
    pub(crate) data_lakes: ::std::option::Option<::std::vec::Vec<crate::types::DataLakeResource>>,
    _request_id: Option<String>,
}
impl CreateDataLakeOutputBuilder {
    /// Appends an item to `data_lakes`.
    ///
    /// To override the contents of this collection use [`set_data_lakes`](Self::set_data_lakes).
    ///
    /// <p>The created Security Lake configuration object.</p>
    pub fn data_lakes(mut self, input: crate::types::DataLakeResource) -> Self {
        let mut v = self.data_lakes.unwrap_or_default();
        v.push(input);
        self.data_lakes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The created Security Lake configuration object.</p>
    pub fn set_data_lakes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DataLakeResource>>) -> Self {
        self.data_lakes = input;
        self
    }
    /// <p>The created Security Lake configuration object.</p>
    pub fn get_data_lakes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DataLakeResource>> {
        &self.data_lakes
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateDataLakeOutput`](crate::operation::create_data_lake::CreateDataLakeOutput).
    pub fn build(self) -> crate::operation::create_data_lake::CreateDataLakeOutput {
        crate::operation::create_data_lake::CreateDataLakeOutput {
            data_lakes: self.data_lakes,
            _request_id: self._request_id,
        }
    }
}
