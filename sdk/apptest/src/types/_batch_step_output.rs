// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines a batch step output.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchStepOutput {
    /// <p>The data set export location of the batch step output.</p>
    pub data_set_export_location: ::std::option::Option<::std::string::String>,
    /// <p>The Database Migration Service (DMS) output location of the batch step output.</p>
    pub dms_output_location: ::std::option::Option<::std::string::String>,
    /// <p>The data set details of the batch step output.</p>
    pub data_set_details: ::std::option::Option<::std::vec::Vec<crate::types::DataSet>>,
}
impl BatchStepOutput {
    /// <p>The data set export location of the batch step output.</p>
    pub fn data_set_export_location(&self) -> ::std::option::Option<&str> {
        self.data_set_export_location.as_deref()
    }
    /// <p>The Database Migration Service (DMS) output location of the batch step output.</p>
    pub fn dms_output_location(&self) -> ::std::option::Option<&str> {
        self.dms_output_location.as_deref()
    }
    /// <p>The data set details of the batch step output.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.data_set_details.is_none()`.
    pub fn data_set_details(&self) -> &[crate::types::DataSet] {
        self.data_set_details.as_deref().unwrap_or_default()
    }
}
impl BatchStepOutput {
    /// Creates a new builder-style object to manufacture [`BatchStepOutput`](crate::types::BatchStepOutput).
    pub fn builder() -> crate::types::builders::BatchStepOutputBuilder {
        crate::types::builders::BatchStepOutputBuilder::default()
    }
}

/// A builder for [`BatchStepOutput`](crate::types::BatchStepOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchStepOutputBuilder {
    pub(crate) data_set_export_location: ::std::option::Option<::std::string::String>,
    pub(crate) dms_output_location: ::std::option::Option<::std::string::String>,
    pub(crate) data_set_details: ::std::option::Option<::std::vec::Vec<crate::types::DataSet>>,
}
impl BatchStepOutputBuilder {
    /// <p>The data set export location of the batch step output.</p>
    pub fn data_set_export_location(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_set_export_location = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The data set export location of the batch step output.</p>
    pub fn set_data_set_export_location(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_set_export_location = input;
        self
    }
    /// <p>The data set export location of the batch step output.</p>
    pub fn get_data_set_export_location(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_set_export_location
    }
    /// <p>The Database Migration Service (DMS) output location of the batch step output.</p>
    pub fn dms_output_location(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dms_output_location = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Database Migration Service (DMS) output location of the batch step output.</p>
    pub fn set_dms_output_location(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dms_output_location = input;
        self
    }
    /// <p>The Database Migration Service (DMS) output location of the batch step output.</p>
    pub fn get_dms_output_location(&self) -> &::std::option::Option<::std::string::String> {
        &self.dms_output_location
    }
    /// Appends an item to `data_set_details`.
    ///
    /// To override the contents of this collection use [`set_data_set_details`](Self::set_data_set_details).
    ///
    /// <p>The data set details of the batch step output.</p>
    pub fn data_set_details(mut self, input: crate::types::DataSet) -> Self {
        let mut v = self.data_set_details.unwrap_or_default();
        v.push(input);
        self.data_set_details = ::std::option::Option::Some(v);
        self
    }
    /// <p>The data set details of the batch step output.</p>
    pub fn set_data_set_details(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DataSet>>) -> Self {
        self.data_set_details = input;
        self
    }
    /// <p>The data set details of the batch step output.</p>
    pub fn get_data_set_details(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DataSet>> {
        &self.data_set_details
    }
    /// Consumes the builder and constructs a [`BatchStepOutput`](crate::types::BatchStepOutput).
    pub fn build(self) -> crate::types::BatchStepOutput {
        crate::types::BatchStepOutput {
            data_set_export_location: self.data_set_export_location,
            dms_output_location: self.dms_output_location,
            data_set_details: self.data_set_details,
        }
    }
}
