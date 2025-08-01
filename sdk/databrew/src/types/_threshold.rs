// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The threshold used with a non-aggregate check expression. The non-aggregate check expression will be applied to each row in a specific column. Then the threshold will be used to determine whether the validation succeeds.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Threshold {
    /// <p>The value of a threshold.</p>
    pub value: f64,
    /// <p>The type of a threshold. Used for comparison of an actual count of rows that satisfy the rule to the threshold value.</p>
    pub r#type: ::std::option::Option<crate::types::ThresholdType>,
    /// <p>Unit of threshold value. Can be either a COUNT or PERCENTAGE of the full sample size used for validation.</p>
    pub unit: ::std::option::Option<crate::types::ThresholdUnit>,
}
impl Threshold {
    /// <p>The value of a threshold.</p>
    pub fn value(&self) -> f64 {
        self.value
    }
    /// <p>The type of a threshold. Used for comparison of an actual count of rows that satisfy the rule to the threshold value.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::ThresholdType> {
        self.r#type.as_ref()
    }
    /// <p>Unit of threshold value. Can be either a COUNT or PERCENTAGE of the full sample size used for validation.</p>
    pub fn unit(&self) -> ::std::option::Option<&crate::types::ThresholdUnit> {
        self.unit.as_ref()
    }
}
impl Threshold {
    /// Creates a new builder-style object to manufacture [`Threshold`](crate::types::Threshold).
    pub fn builder() -> crate::types::builders::ThresholdBuilder {
        crate::types::builders::ThresholdBuilder::default()
    }
}

/// A builder for [`Threshold`](crate::types::Threshold).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ThresholdBuilder {
    pub(crate) value: ::std::option::Option<f64>,
    pub(crate) r#type: ::std::option::Option<crate::types::ThresholdType>,
    pub(crate) unit: ::std::option::Option<crate::types::ThresholdUnit>,
}
impl ThresholdBuilder {
    /// <p>The value of a threshold.</p>
    /// This field is required.
    pub fn value(mut self, input: f64) -> Self {
        self.value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The value of a threshold.</p>
    pub fn set_value(mut self, input: ::std::option::Option<f64>) -> Self {
        self.value = input;
        self
    }
    /// <p>The value of a threshold.</p>
    pub fn get_value(&self) -> &::std::option::Option<f64> {
        &self.value
    }
    /// <p>The type of a threshold. Used for comparison of an actual count of rows that satisfy the rule to the threshold value.</p>
    pub fn r#type(mut self, input: crate::types::ThresholdType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of a threshold. Used for comparison of an actual count of rows that satisfy the rule to the threshold value.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::ThresholdType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of a threshold. Used for comparison of an actual count of rows that satisfy the rule to the threshold value.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::ThresholdType> {
        &self.r#type
    }
    /// <p>Unit of threshold value. Can be either a COUNT or PERCENTAGE of the full sample size used for validation.</p>
    pub fn unit(mut self, input: crate::types::ThresholdUnit) -> Self {
        self.unit = ::std::option::Option::Some(input);
        self
    }
    /// <p>Unit of threshold value. Can be either a COUNT or PERCENTAGE of the full sample size used for validation.</p>
    pub fn set_unit(mut self, input: ::std::option::Option<crate::types::ThresholdUnit>) -> Self {
        self.unit = input;
        self
    }
    /// <p>Unit of threshold value. Can be either a COUNT or PERCENTAGE of the full sample size used for validation.</p>
    pub fn get_unit(&self) -> &::std::option::Option<crate::types::ThresholdUnit> {
        &self.unit
    }
    /// Consumes the builder and constructs a [`Threshold`](crate::types::Threshold).
    pub fn build(self) -> crate::types::Threshold {
        crate::types::Threshold {
            value: self.value.unwrap_or_default(),
            r#type: self.r#type,
            unit: self.unit,
        }
    }
}
