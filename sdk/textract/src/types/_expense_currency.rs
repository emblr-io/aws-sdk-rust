// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Returns the kind of currency detected.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExpenseCurrency {
    /// <p>Currency code for detected currency. the current supported codes are:</p>
    /// <ul>
    /// <li>
    /// <p>USD</p></li>
    /// <li>
    /// <p>EUR</p></li>
    /// <li>
    /// <p>GBP</p></li>
    /// <li>
    /// <p>CAD</p></li>
    /// <li>
    /// <p>INR</p></li>
    /// <li>
    /// <p>JPY</p></li>
    /// <li>
    /// <p>CHF</p></li>
    /// <li>
    /// <p>AUD</p></li>
    /// <li>
    /// <p>CNY</p></li>
    /// <li>
    /// <p>BZR</p></li>
    /// <li>
    /// <p>SEK</p></li>
    /// <li>
    /// <p>HKD</p></li>
    /// </ul>
    pub code: ::std::option::Option<::std::string::String>,
    /// <p>Percentage confideence in the detected currency.</p>
    pub confidence: ::std::option::Option<f32>,
}
impl ExpenseCurrency {
    /// <p>Currency code for detected currency. the current supported codes are:</p>
    /// <ul>
    /// <li>
    /// <p>USD</p></li>
    /// <li>
    /// <p>EUR</p></li>
    /// <li>
    /// <p>GBP</p></li>
    /// <li>
    /// <p>CAD</p></li>
    /// <li>
    /// <p>INR</p></li>
    /// <li>
    /// <p>JPY</p></li>
    /// <li>
    /// <p>CHF</p></li>
    /// <li>
    /// <p>AUD</p></li>
    /// <li>
    /// <p>CNY</p></li>
    /// <li>
    /// <p>BZR</p></li>
    /// <li>
    /// <p>SEK</p></li>
    /// <li>
    /// <p>HKD</p></li>
    /// </ul>
    pub fn code(&self) -> ::std::option::Option<&str> {
        self.code.as_deref()
    }
    /// <p>Percentage confideence in the detected currency.</p>
    pub fn confidence(&self) -> ::std::option::Option<f32> {
        self.confidence
    }
}
impl ExpenseCurrency {
    /// Creates a new builder-style object to manufacture [`ExpenseCurrency`](crate::types::ExpenseCurrency).
    pub fn builder() -> crate::types::builders::ExpenseCurrencyBuilder {
        crate::types::builders::ExpenseCurrencyBuilder::default()
    }
}

/// A builder for [`ExpenseCurrency`](crate::types::ExpenseCurrency).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExpenseCurrencyBuilder {
    pub(crate) code: ::std::option::Option<::std::string::String>,
    pub(crate) confidence: ::std::option::Option<f32>,
}
impl ExpenseCurrencyBuilder {
    /// <p>Currency code for detected currency. the current supported codes are:</p>
    /// <ul>
    /// <li>
    /// <p>USD</p></li>
    /// <li>
    /// <p>EUR</p></li>
    /// <li>
    /// <p>GBP</p></li>
    /// <li>
    /// <p>CAD</p></li>
    /// <li>
    /// <p>INR</p></li>
    /// <li>
    /// <p>JPY</p></li>
    /// <li>
    /// <p>CHF</p></li>
    /// <li>
    /// <p>AUD</p></li>
    /// <li>
    /// <p>CNY</p></li>
    /// <li>
    /// <p>BZR</p></li>
    /// <li>
    /// <p>SEK</p></li>
    /// <li>
    /// <p>HKD</p></li>
    /// </ul>
    pub fn code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Currency code for detected currency. the current supported codes are:</p>
    /// <ul>
    /// <li>
    /// <p>USD</p></li>
    /// <li>
    /// <p>EUR</p></li>
    /// <li>
    /// <p>GBP</p></li>
    /// <li>
    /// <p>CAD</p></li>
    /// <li>
    /// <p>INR</p></li>
    /// <li>
    /// <p>JPY</p></li>
    /// <li>
    /// <p>CHF</p></li>
    /// <li>
    /// <p>AUD</p></li>
    /// <li>
    /// <p>CNY</p></li>
    /// <li>
    /// <p>BZR</p></li>
    /// <li>
    /// <p>SEK</p></li>
    /// <li>
    /// <p>HKD</p></li>
    /// </ul>
    pub fn set_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.code = input;
        self
    }
    /// <p>Currency code for detected currency. the current supported codes are:</p>
    /// <ul>
    /// <li>
    /// <p>USD</p></li>
    /// <li>
    /// <p>EUR</p></li>
    /// <li>
    /// <p>GBP</p></li>
    /// <li>
    /// <p>CAD</p></li>
    /// <li>
    /// <p>INR</p></li>
    /// <li>
    /// <p>JPY</p></li>
    /// <li>
    /// <p>CHF</p></li>
    /// <li>
    /// <p>AUD</p></li>
    /// <li>
    /// <p>CNY</p></li>
    /// <li>
    /// <p>BZR</p></li>
    /// <li>
    /// <p>SEK</p></li>
    /// <li>
    /// <p>HKD</p></li>
    /// </ul>
    pub fn get_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.code
    }
    /// <p>Percentage confideence in the detected currency.</p>
    pub fn confidence(mut self, input: f32) -> Self {
        self.confidence = ::std::option::Option::Some(input);
        self
    }
    /// <p>Percentage confideence in the detected currency.</p>
    pub fn set_confidence(mut self, input: ::std::option::Option<f32>) -> Self {
        self.confidence = input;
        self
    }
    /// <p>Percentage confideence in the detected currency.</p>
    pub fn get_confidence(&self) -> &::std::option::Option<f32> {
        &self.confidence
    }
    /// Consumes the builder and constructs a [`ExpenseCurrency`](crate::types::ExpenseCurrency).
    pub fn build(self) -> crate::types::ExpenseCurrency {
        crate::types::ExpenseCurrency {
            code: self.code,
            confidence: self.confidence,
        }
    }
}
