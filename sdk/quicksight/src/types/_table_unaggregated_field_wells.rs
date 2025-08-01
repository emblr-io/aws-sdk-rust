// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The unaggregated field well for the table.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TableUnaggregatedFieldWells {
    /// <p>The values field well for a pivot table. Values are unaggregated for an unaggregated table.</p>
    pub values: ::std::option::Option<::std::vec::Vec<crate::types::UnaggregatedField>>,
}
impl TableUnaggregatedFieldWells {
    /// <p>The values field well for a pivot table. Values are unaggregated for an unaggregated table.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.values.is_none()`.
    pub fn values(&self) -> &[crate::types::UnaggregatedField] {
        self.values.as_deref().unwrap_or_default()
    }
}
impl TableUnaggregatedFieldWells {
    /// Creates a new builder-style object to manufacture [`TableUnaggregatedFieldWells`](crate::types::TableUnaggregatedFieldWells).
    pub fn builder() -> crate::types::builders::TableUnaggregatedFieldWellsBuilder {
        crate::types::builders::TableUnaggregatedFieldWellsBuilder::default()
    }
}

/// A builder for [`TableUnaggregatedFieldWells`](crate::types::TableUnaggregatedFieldWells).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TableUnaggregatedFieldWellsBuilder {
    pub(crate) values: ::std::option::Option<::std::vec::Vec<crate::types::UnaggregatedField>>,
}
impl TableUnaggregatedFieldWellsBuilder {
    /// Appends an item to `values`.
    ///
    /// To override the contents of this collection use [`set_values`](Self::set_values).
    ///
    /// <p>The values field well for a pivot table. Values are unaggregated for an unaggregated table.</p>
    pub fn values(mut self, input: crate::types::UnaggregatedField) -> Self {
        let mut v = self.values.unwrap_or_default();
        v.push(input);
        self.values = ::std::option::Option::Some(v);
        self
    }
    /// <p>The values field well for a pivot table. Values are unaggregated for an unaggregated table.</p>
    pub fn set_values(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::UnaggregatedField>>) -> Self {
        self.values = input;
        self
    }
    /// <p>The values field well for a pivot table. Values are unaggregated for an unaggregated table.</p>
    pub fn get_values(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UnaggregatedField>> {
        &self.values
    }
    /// Consumes the builder and constructs a [`TableUnaggregatedFieldWells`](crate::types::TableUnaggregatedFieldWells).
    pub fn build(self) -> crate::types::TableUnaggregatedFieldWells {
        crate::types::TableUnaggregatedFieldWells { values: self.values }
    }
}
