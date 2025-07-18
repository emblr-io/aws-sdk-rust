// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies maintenance schedule duration: duration value and duration unit. See the <a href="https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/auto-tune.html" target="_blank">Developer Guide</a> for more information.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Duration {
    /// <p>Integer to specify the value of a maintenance schedule duration. See the <a href="https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/auto-tune.html" target="_blank">Developer Guide</a> for more information.</p>
    pub value: ::std::option::Option<i64>,
    /// <p>Specifies the unit of a maintenance schedule duration. Valid value is HOURS. See the <a href="https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/auto-tune.html" target="_blank">Developer Guide</a> for more information.</p>
    pub unit: ::std::option::Option<crate::types::TimeUnit>,
}
impl Duration {
    /// <p>Integer to specify the value of a maintenance schedule duration. See the <a href="https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/auto-tune.html" target="_blank">Developer Guide</a> for more information.</p>
    pub fn value(&self) -> ::std::option::Option<i64> {
        self.value
    }
    /// <p>Specifies the unit of a maintenance schedule duration. Valid value is HOURS. See the <a href="https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/auto-tune.html" target="_blank">Developer Guide</a> for more information.</p>
    pub fn unit(&self) -> ::std::option::Option<&crate::types::TimeUnit> {
        self.unit.as_ref()
    }
}
impl Duration {
    /// Creates a new builder-style object to manufacture [`Duration`](crate::types::Duration).
    pub fn builder() -> crate::types::builders::DurationBuilder {
        crate::types::builders::DurationBuilder::default()
    }
}

/// A builder for [`Duration`](crate::types::Duration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DurationBuilder {
    pub(crate) value: ::std::option::Option<i64>,
    pub(crate) unit: ::std::option::Option<crate::types::TimeUnit>,
}
impl DurationBuilder {
    /// <p>Integer to specify the value of a maintenance schedule duration. See the <a href="https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/auto-tune.html" target="_blank">Developer Guide</a> for more information.</p>
    pub fn value(mut self, input: i64) -> Self {
        self.value = ::std::option::Option::Some(input);
        self
    }
    /// <p>Integer to specify the value of a maintenance schedule duration. See the <a href="https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/auto-tune.html" target="_blank">Developer Guide</a> for more information.</p>
    pub fn set_value(mut self, input: ::std::option::Option<i64>) -> Self {
        self.value = input;
        self
    }
    /// <p>Integer to specify the value of a maintenance schedule duration. See the <a href="https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/auto-tune.html" target="_blank">Developer Guide</a> for more information.</p>
    pub fn get_value(&self) -> &::std::option::Option<i64> {
        &self.value
    }
    /// <p>Specifies the unit of a maintenance schedule duration. Valid value is HOURS. See the <a href="https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/auto-tune.html" target="_blank">Developer Guide</a> for more information.</p>
    pub fn unit(mut self, input: crate::types::TimeUnit) -> Self {
        self.unit = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the unit of a maintenance schedule duration. Valid value is HOURS. See the <a href="https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/auto-tune.html" target="_blank">Developer Guide</a> for more information.</p>
    pub fn set_unit(mut self, input: ::std::option::Option<crate::types::TimeUnit>) -> Self {
        self.unit = input;
        self
    }
    /// <p>Specifies the unit of a maintenance schedule duration. Valid value is HOURS. See the <a href="https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/auto-tune.html" target="_blank">Developer Guide</a> for more information.</p>
    pub fn get_unit(&self) -> &::std::option::Option<crate::types::TimeUnit> {
        &self.unit
    }
    /// Consumes the builder and constructs a [`Duration`](crate::types::Duration).
    pub fn build(self) -> crate::types::Duration {
        crate::types::Duration {
            value: self.value,
            unit: self.unit,
        }
    }
}
