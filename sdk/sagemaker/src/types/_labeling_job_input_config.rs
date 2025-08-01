// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Input configuration information for a labeling job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LabelingJobInputConfig {
    /// <p>The location of the input data.</p>
    pub data_source: ::std::option::Option<crate::types::LabelingJobDataSource>,
    /// <p>Attributes of the data specified by the customer.</p>
    pub data_attributes: ::std::option::Option<crate::types::LabelingJobDataAttributes>,
}
impl LabelingJobInputConfig {
    /// <p>The location of the input data.</p>
    pub fn data_source(&self) -> ::std::option::Option<&crate::types::LabelingJobDataSource> {
        self.data_source.as_ref()
    }
    /// <p>Attributes of the data specified by the customer.</p>
    pub fn data_attributes(&self) -> ::std::option::Option<&crate::types::LabelingJobDataAttributes> {
        self.data_attributes.as_ref()
    }
}
impl LabelingJobInputConfig {
    /// Creates a new builder-style object to manufacture [`LabelingJobInputConfig`](crate::types::LabelingJobInputConfig).
    pub fn builder() -> crate::types::builders::LabelingJobInputConfigBuilder {
        crate::types::builders::LabelingJobInputConfigBuilder::default()
    }
}

/// A builder for [`LabelingJobInputConfig`](crate::types::LabelingJobInputConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LabelingJobInputConfigBuilder {
    pub(crate) data_source: ::std::option::Option<crate::types::LabelingJobDataSource>,
    pub(crate) data_attributes: ::std::option::Option<crate::types::LabelingJobDataAttributes>,
}
impl LabelingJobInputConfigBuilder {
    /// <p>The location of the input data.</p>
    /// This field is required.
    pub fn data_source(mut self, input: crate::types::LabelingJobDataSource) -> Self {
        self.data_source = ::std::option::Option::Some(input);
        self
    }
    /// <p>The location of the input data.</p>
    pub fn set_data_source(mut self, input: ::std::option::Option<crate::types::LabelingJobDataSource>) -> Self {
        self.data_source = input;
        self
    }
    /// <p>The location of the input data.</p>
    pub fn get_data_source(&self) -> &::std::option::Option<crate::types::LabelingJobDataSource> {
        &self.data_source
    }
    /// <p>Attributes of the data specified by the customer.</p>
    pub fn data_attributes(mut self, input: crate::types::LabelingJobDataAttributes) -> Self {
        self.data_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Attributes of the data specified by the customer.</p>
    pub fn set_data_attributes(mut self, input: ::std::option::Option<crate::types::LabelingJobDataAttributes>) -> Self {
        self.data_attributes = input;
        self
    }
    /// <p>Attributes of the data specified by the customer.</p>
    pub fn get_data_attributes(&self) -> &::std::option::Option<crate::types::LabelingJobDataAttributes> {
        &self.data_attributes
    }
    /// Consumes the builder and constructs a [`LabelingJobInputConfig`](crate::types::LabelingJobInputConfig).
    pub fn build(self) -> crate::types::LabelingJobInputConfig {
        crate::types::LabelingJobInputConfig {
            data_source: self.data_source,
            data_attributes: self.data_attributes,
        }
    }
}
