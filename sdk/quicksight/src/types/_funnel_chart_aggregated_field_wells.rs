// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The field well configuration of a <code>FunnelChartVisual</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FunnelChartAggregatedFieldWells {
    /// <p>The category field wells of a funnel chart. Values are grouped by category fields.</p>
    pub category: ::std::option::Option<::std::vec::Vec<crate::types::DimensionField>>,
    /// <p>The value field wells of a funnel chart. Values are aggregated based on categories.</p>
    pub values: ::std::option::Option<::std::vec::Vec<crate::types::MeasureField>>,
}
impl FunnelChartAggregatedFieldWells {
    /// <p>The category field wells of a funnel chart. Values are grouped by category fields.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.category.is_none()`.
    pub fn category(&self) -> &[crate::types::DimensionField] {
        self.category.as_deref().unwrap_or_default()
    }
    /// <p>The value field wells of a funnel chart. Values are aggregated based on categories.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.values.is_none()`.
    pub fn values(&self) -> &[crate::types::MeasureField] {
        self.values.as_deref().unwrap_or_default()
    }
}
impl FunnelChartAggregatedFieldWells {
    /// Creates a new builder-style object to manufacture [`FunnelChartAggregatedFieldWells`](crate::types::FunnelChartAggregatedFieldWells).
    pub fn builder() -> crate::types::builders::FunnelChartAggregatedFieldWellsBuilder {
        crate::types::builders::FunnelChartAggregatedFieldWellsBuilder::default()
    }
}

/// A builder for [`FunnelChartAggregatedFieldWells`](crate::types::FunnelChartAggregatedFieldWells).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FunnelChartAggregatedFieldWellsBuilder {
    pub(crate) category: ::std::option::Option<::std::vec::Vec<crate::types::DimensionField>>,
    pub(crate) values: ::std::option::Option<::std::vec::Vec<crate::types::MeasureField>>,
}
impl FunnelChartAggregatedFieldWellsBuilder {
    /// Appends an item to `category`.
    ///
    /// To override the contents of this collection use [`set_category`](Self::set_category).
    ///
    /// <p>The category field wells of a funnel chart. Values are grouped by category fields.</p>
    pub fn category(mut self, input: crate::types::DimensionField) -> Self {
        let mut v = self.category.unwrap_or_default();
        v.push(input);
        self.category = ::std::option::Option::Some(v);
        self
    }
    /// <p>The category field wells of a funnel chart. Values are grouped by category fields.</p>
    pub fn set_category(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DimensionField>>) -> Self {
        self.category = input;
        self
    }
    /// <p>The category field wells of a funnel chart. Values are grouped by category fields.</p>
    pub fn get_category(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DimensionField>> {
        &self.category
    }
    /// Appends an item to `values`.
    ///
    /// To override the contents of this collection use [`set_values`](Self::set_values).
    ///
    /// <p>The value field wells of a funnel chart. Values are aggregated based on categories.</p>
    pub fn values(mut self, input: crate::types::MeasureField) -> Self {
        let mut v = self.values.unwrap_or_default();
        v.push(input);
        self.values = ::std::option::Option::Some(v);
        self
    }
    /// <p>The value field wells of a funnel chart. Values are aggregated based on categories.</p>
    pub fn set_values(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MeasureField>>) -> Self {
        self.values = input;
        self
    }
    /// <p>The value field wells of a funnel chart. Values are aggregated based on categories.</p>
    pub fn get_values(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MeasureField>> {
        &self.values
    }
    /// Consumes the builder and constructs a [`FunnelChartAggregatedFieldWells`](crate::types::FunnelChartAggregatedFieldWells).
    pub fn build(self) -> crate::types::FunnelChartAggregatedFieldWells {
        crate::types::FunnelChartAggregatedFieldWells {
            category: self.category,
            values: self.values,
        }
    }
}
