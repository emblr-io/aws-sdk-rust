// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Parameters that define how to split a dataset into training data and testing data, and the number of iterations to perform. These parameters are specified in the predefined algorithms but you can override them in the <code>CreatePredictor</code> request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EvaluationParameters {
    /// <p>The number of times to split the input data. The default is 1. Valid values are 1 through 5.</p>
    pub number_of_backtest_windows: ::std::option::Option<i32>,
    /// <p>The point from the end of the dataset where you want to split the data for model training and testing (evaluation). Specify the value as the number of data points. The default is the value of the forecast horizon. <code>BackTestWindowOffset</code> can be used to mimic a past virtual forecast start date. This value must be greater than or equal to the forecast horizon and less than half of the TARGET_TIME_SERIES dataset length.</p>
    /// <p><code>ForecastHorizon</code> &lt;= <code>BackTestWindowOffset</code> &lt; 1/2 * TARGET_TIME_SERIES dataset length</p>
    pub back_test_window_offset: ::std::option::Option<i32>,
}
impl EvaluationParameters {
    /// <p>The number of times to split the input data. The default is 1. Valid values are 1 through 5.</p>
    pub fn number_of_backtest_windows(&self) -> ::std::option::Option<i32> {
        self.number_of_backtest_windows
    }
    /// <p>The point from the end of the dataset where you want to split the data for model training and testing (evaluation). Specify the value as the number of data points. The default is the value of the forecast horizon. <code>BackTestWindowOffset</code> can be used to mimic a past virtual forecast start date. This value must be greater than or equal to the forecast horizon and less than half of the TARGET_TIME_SERIES dataset length.</p>
    /// <p><code>ForecastHorizon</code> &lt;= <code>BackTestWindowOffset</code> &lt; 1/2 * TARGET_TIME_SERIES dataset length</p>
    pub fn back_test_window_offset(&self) -> ::std::option::Option<i32> {
        self.back_test_window_offset
    }
}
impl EvaluationParameters {
    /// Creates a new builder-style object to manufacture [`EvaluationParameters`](crate::types::EvaluationParameters).
    pub fn builder() -> crate::types::builders::EvaluationParametersBuilder {
        crate::types::builders::EvaluationParametersBuilder::default()
    }
}

/// A builder for [`EvaluationParameters`](crate::types::EvaluationParameters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EvaluationParametersBuilder {
    pub(crate) number_of_backtest_windows: ::std::option::Option<i32>,
    pub(crate) back_test_window_offset: ::std::option::Option<i32>,
}
impl EvaluationParametersBuilder {
    /// <p>The number of times to split the input data. The default is 1. Valid values are 1 through 5.</p>
    pub fn number_of_backtest_windows(mut self, input: i32) -> Self {
        self.number_of_backtest_windows = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of times to split the input data. The default is 1. Valid values are 1 through 5.</p>
    pub fn set_number_of_backtest_windows(mut self, input: ::std::option::Option<i32>) -> Self {
        self.number_of_backtest_windows = input;
        self
    }
    /// <p>The number of times to split the input data. The default is 1. Valid values are 1 through 5.</p>
    pub fn get_number_of_backtest_windows(&self) -> &::std::option::Option<i32> {
        &self.number_of_backtest_windows
    }
    /// <p>The point from the end of the dataset where you want to split the data for model training and testing (evaluation). Specify the value as the number of data points. The default is the value of the forecast horizon. <code>BackTestWindowOffset</code> can be used to mimic a past virtual forecast start date. This value must be greater than or equal to the forecast horizon and less than half of the TARGET_TIME_SERIES dataset length.</p>
    /// <p><code>ForecastHorizon</code> &lt;= <code>BackTestWindowOffset</code> &lt; 1/2 * TARGET_TIME_SERIES dataset length</p>
    pub fn back_test_window_offset(mut self, input: i32) -> Self {
        self.back_test_window_offset = ::std::option::Option::Some(input);
        self
    }
    /// <p>The point from the end of the dataset where you want to split the data for model training and testing (evaluation). Specify the value as the number of data points. The default is the value of the forecast horizon. <code>BackTestWindowOffset</code> can be used to mimic a past virtual forecast start date. This value must be greater than or equal to the forecast horizon and less than half of the TARGET_TIME_SERIES dataset length.</p>
    /// <p><code>ForecastHorizon</code> &lt;= <code>BackTestWindowOffset</code> &lt; 1/2 * TARGET_TIME_SERIES dataset length</p>
    pub fn set_back_test_window_offset(mut self, input: ::std::option::Option<i32>) -> Self {
        self.back_test_window_offset = input;
        self
    }
    /// <p>The point from the end of the dataset where you want to split the data for model training and testing (evaluation). Specify the value as the number of data points. The default is the value of the forecast horizon. <code>BackTestWindowOffset</code> can be used to mimic a past virtual forecast start date. This value must be greater than or equal to the forecast horizon and less than half of the TARGET_TIME_SERIES dataset length.</p>
    /// <p><code>ForecastHorizon</code> &lt;= <code>BackTestWindowOffset</code> &lt; 1/2 * TARGET_TIME_SERIES dataset length</p>
    pub fn get_back_test_window_offset(&self) -> &::std::option::Option<i32> {
        &self.back_test_window_offset
    }
    /// Consumes the builder and constructs a [`EvaluationParameters`](crate::types::EvaluationParameters).
    pub fn build(self) -> crate::types::EvaluationParameters {
        crate::types::EvaluationParameters {
            number_of_backtest_windows: self.number_of_backtest_windows,
            back_test_window_offset: self.back_test_window_offset,
        }
    }
}
