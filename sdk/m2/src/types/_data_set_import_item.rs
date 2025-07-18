// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Identifies a specific data set to import from an external location.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DataSetImportItem {
    /// <p>The data set.</p>
    pub data_set: ::std::option::Option<crate::types::DataSet>,
    /// <p>The location of the data set.</p>
    pub external_location: ::std::option::Option<crate::types::ExternalLocation>,
}
impl DataSetImportItem {
    /// <p>The data set.</p>
    pub fn data_set(&self) -> ::std::option::Option<&crate::types::DataSet> {
        self.data_set.as_ref()
    }
    /// <p>The location of the data set.</p>
    pub fn external_location(&self) -> ::std::option::Option<&crate::types::ExternalLocation> {
        self.external_location.as_ref()
    }
}
impl DataSetImportItem {
    /// Creates a new builder-style object to manufacture [`DataSetImportItem`](crate::types::DataSetImportItem).
    pub fn builder() -> crate::types::builders::DataSetImportItemBuilder {
        crate::types::builders::DataSetImportItemBuilder::default()
    }
}

/// A builder for [`DataSetImportItem`](crate::types::DataSetImportItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DataSetImportItemBuilder {
    pub(crate) data_set: ::std::option::Option<crate::types::DataSet>,
    pub(crate) external_location: ::std::option::Option<crate::types::ExternalLocation>,
}
impl DataSetImportItemBuilder {
    /// <p>The data set.</p>
    /// This field is required.
    pub fn data_set(mut self, input: crate::types::DataSet) -> Self {
        self.data_set = ::std::option::Option::Some(input);
        self
    }
    /// <p>The data set.</p>
    pub fn set_data_set(mut self, input: ::std::option::Option<crate::types::DataSet>) -> Self {
        self.data_set = input;
        self
    }
    /// <p>The data set.</p>
    pub fn get_data_set(&self) -> &::std::option::Option<crate::types::DataSet> {
        &self.data_set
    }
    /// <p>The location of the data set.</p>
    /// This field is required.
    pub fn external_location(mut self, input: crate::types::ExternalLocation) -> Self {
        self.external_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>The location of the data set.</p>
    pub fn set_external_location(mut self, input: ::std::option::Option<crate::types::ExternalLocation>) -> Self {
        self.external_location = input;
        self
    }
    /// <p>The location of the data set.</p>
    pub fn get_external_location(&self) -> &::std::option::Option<crate::types::ExternalLocation> {
        &self.external_location
    }
    /// Consumes the builder and constructs a [`DataSetImportItem`](crate::types::DataSetImportItem).
    pub fn build(self) -> crate::types::DataSetImportItem {
        crate::types::DataSetImportItem {
            data_set: self.data_set,
            external_location: self.external_location,
        }
    }
}
