// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Data retrieval policy rule.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DataRetrievalRule {
    /// <p>The type of data retrieval policy to set.</p>
    /// <p>Valid values: BytesPerHour|FreeTier|None</p>
    pub strategy: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of bytes that can be retrieved in an hour.</p>
    /// <p>This field is required only if the value of the Strategy field is <code>BytesPerHour</code>. Your PUT operation will be rejected if the Strategy field is not set to <code>BytesPerHour</code> and you set this field.</p>
    pub bytes_per_hour: ::std::option::Option<i64>,
}
impl DataRetrievalRule {
    /// <p>The type of data retrieval policy to set.</p>
    /// <p>Valid values: BytesPerHour|FreeTier|None</p>
    pub fn strategy(&self) -> ::std::option::Option<&str> {
        self.strategy.as_deref()
    }
    /// <p>The maximum number of bytes that can be retrieved in an hour.</p>
    /// <p>This field is required only if the value of the Strategy field is <code>BytesPerHour</code>. Your PUT operation will be rejected if the Strategy field is not set to <code>BytesPerHour</code> and you set this field.</p>
    pub fn bytes_per_hour(&self) -> ::std::option::Option<i64> {
        self.bytes_per_hour
    }
}
impl DataRetrievalRule {
    /// Creates a new builder-style object to manufacture [`DataRetrievalRule`](crate::types::DataRetrievalRule).
    pub fn builder() -> crate::types::builders::DataRetrievalRuleBuilder {
        crate::types::builders::DataRetrievalRuleBuilder::default()
    }
}

/// A builder for [`DataRetrievalRule`](crate::types::DataRetrievalRule).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DataRetrievalRuleBuilder {
    pub(crate) strategy: ::std::option::Option<::std::string::String>,
    pub(crate) bytes_per_hour: ::std::option::Option<i64>,
}
impl DataRetrievalRuleBuilder {
    /// <p>The type of data retrieval policy to set.</p>
    /// <p>Valid values: BytesPerHour|FreeTier|None</p>
    pub fn strategy(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.strategy = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of data retrieval policy to set.</p>
    /// <p>Valid values: BytesPerHour|FreeTier|None</p>
    pub fn set_strategy(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.strategy = input;
        self
    }
    /// <p>The type of data retrieval policy to set.</p>
    /// <p>Valid values: BytesPerHour|FreeTier|None</p>
    pub fn get_strategy(&self) -> &::std::option::Option<::std::string::String> {
        &self.strategy
    }
    /// <p>The maximum number of bytes that can be retrieved in an hour.</p>
    /// <p>This field is required only if the value of the Strategy field is <code>BytesPerHour</code>. Your PUT operation will be rejected if the Strategy field is not set to <code>BytesPerHour</code> and you set this field.</p>
    pub fn bytes_per_hour(mut self, input: i64) -> Self {
        self.bytes_per_hour = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of bytes that can be retrieved in an hour.</p>
    /// <p>This field is required only if the value of the Strategy field is <code>BytesPerHour</code>. Your PUT operation will be rejected if the Strategy field is not set to <code>BytesPerHour</code> and you set this field.</p>
    pub fn set_bytes_per_hour(mut self, input: ::std::option::Option<i64>) -> Self {
        self.bytes_per_hour = input;
        self
    }
    /// <p>The maximum number of bytes that can be retrieved in an hour.</p>
    /// <p>This field is required only if the value of the Strategy field is <code>BytesPerHour</code>. Your PUT operation will be rejected if the Strategy field is not set to <code>BytesPerHour</code> and you set this field.</p>
    pub fn get_bytes_per_hour(&self) -> &::std::option::Option<i64> {
        &self.bytes_per_hour
    }
    /// Consumes the builder and constructs a [`DataRetrievalRule`](crate::types::DataRetrievalRule).
    pub fn build(self) -> crate::types::DataRetrievalRule {
        crate::types::DataRetrievalRule {
            strategy: self.strategy,
            bytes_per_hour: self.bytes_per_hour,
        }
    }
}
