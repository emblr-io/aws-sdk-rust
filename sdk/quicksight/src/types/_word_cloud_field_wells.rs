// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The field wells of a word cloud visual.</p>
/// <p>This is a union type structure. For this structure to be valid, only one of the attributes can be defined.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WordCloudFieldWells {
    /// <p>The aggregated field wells of a word cloud.</p>
    pub word_cloud_aggregated_field_wells: ::std::option::Option<crate::types::WordCloudAggregatedFieldWells>,
}
impl WordCloudFieldWells {
    /// <p>The aggregated field wells of a word cloud.</p>
    pub fn word_cloud_aggregated_field_wells(&self) -> ::std::option::Option<&crate::types::WordCloudAggregatedFieldWells> {
        self.word_cloud_aggregated_field_wells.as_ref()
    }
}
impl WordCloudFieldWells {
    /// Creates a new builder-style object to manufacture [`WordCloudFieldWells`](crate::types::WordCloudFieldWells).
    pub fn builder() -> crate::types::builders::WordCloudFieldWellsBuilder {
        crate::types::builders::WordCloudFieldWellsBuilder::default()
    }
}

/// A builder for [`WordCloudFieldWells`](crate::types::WordCloudFieldWells).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WordCloudFieldWellsBuilder {
    pub(crate) word_cloud_aggregated_field_wells: ::std::option::Option<crate::types::WordCloudAggregatedFieldWells>,
}
impl WordCloudFieldWellsBuilder {
    /// <p>The aggregated field wells of a word cloud.</p>
    pub fn word_cloud_aggregated_field_wells(mut self, input: crate::types::WordCloudAggregatedFieldWells) -> Self {
        self.word_cloud_aggregated_field_wells = ::std::option::Option::Some(input);
        self
    }
    /// <p>The aggregated field wells of a word cloud.</p>
    pub fn set_word_cloud_aggregated_field_wells(mut self, input: ::std::option::Option<crate::types::WordCloudAggregatedFieldWells>) -> Self {
        self.word_cloud_aggregated_field_wells = input;
        self
    }
    /// <p>The aggregated field wells of a word cloud.</p>
    pub fn get_word_cloud_aggregated_field_wells(&self) -> &::std::option::Option<crate::types::WordCloudAggregatedFieldWells> {
        &self.word_cloud_aggregated_field_wells
    }
    /// Consumes the builder and constructs a [`WordCloudFieldWells`](crate::types::WordCloudFieldWells).
    pub fn build(self) -> crate::types::WordCloudFieldWells {
        crate::types::WordCloudFieldWells {
            word_cloud_aggregated_field_wells: self.word_cloud_aggregated_field_wells,
        }
    }
}
