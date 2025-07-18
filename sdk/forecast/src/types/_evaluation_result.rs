// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The results of evaluating an algorithm. Returned as part of the <code>GetAccuracyMetrics</code> response.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EvaluationResult {
    /// <p>The Amazon Resource Name (ARN) of the algorithm that was evaluated.</p>
    pub algorithm_arn: ::std::option::Option<::std::string::String>,
    /// <p>The array of test windows used for evaluating the algorithm. The <code>NumberOfBacktestWindows</code> from the <code>EvaluationParameters</code> object determines the number of windows in the array.</p>
    pub test_windows: ::std::option::Option<::std::vec::Vec<crate::types::WindowSummary>>,
}
impl EvaluationResult {
    /// <p>The Amazon Resource Name (ARN) of the algorithm that was evaluated.</p>
    pub fn algorithm_arn(&self) -> ::std::option::Option<&str> {
        self.algorithm_arn.as_deref()
    }
    /// <p>The array of test windows used for evaluating the algorithm. The <code>NumberOfBacktestWindows</code> from the <code>EvaluationParameters</code> object determines the number of windows in the array.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.test_windows.is_none()`.
    pub fn test_windows(&self) -> &[crate::types::WindowSummary] {
        self.test_windows.as_deref().unwrap_or_default()
    }
}
impl EvaluationResult {
    /// Creates a new builder-style object to manufacture [`EvaluationResult`](crate::types::EvaluationResult).
    pub fn builder() -> crate::types::builders::EvaluationResultBuilder {
        crate::types::builders::EvaluationResultBuilder::default()
    }
}

/// A builder for [`EvaluationResult`](crate::types::EvaluationResult).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EvaluationResultBuilder {
    pub(crate) algorithm_arn: ::std::option::Option<::std::string::String>,
    pub(crate) test_windows: ::std::option::Option<::std::vec::Vec<crate::types::WindowSummary>>,
}
impl EvaluationResultBuilder {
    /// <p>The Amazon Resource Name (ARN) of the algorithm that was evaluated.</p>
    pub fn algorithm_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.algorithm_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the algorithm that was evaluated.</p>
    pub fn set_algorithm_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.algorithm_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the algorithm that was evaluated.</p>
    pub fn get_algorithm_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.algorithm_arn
    }
    /// Appends an item to `test_windows`.
    ///
    /// To override the contents of this collection use [`set_test_windows`](Self::set_test_windows).
    ///
    /// <p>The array of test windows used for evaluating the algorithm. The <code>NumberOfBacktestWindows</code> from the <code>EvaluationParameters</code> object determines the number of windows in the array.</p>
    pub fn test_windows(mut self, input: crate::types::WindowSummary) -> Self {
        let mut v = self.test_windows.unwrap_or_default();
        v.push(input);
        self.test_windows = ::std::option::Option::Some(v);
        self
    }
    /// <p>The array of test windows used for evaluating the algorithm. The <code>NumberOfBacktestWindows</code> from the <code>EvaluationParameters</code> object determines the number of windows in the array.</p>
    pub fn set_test_windows(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::WindowSummary>>) -> Self {
        self.test_windows = input;
        self
    }
    /// <p>The array of test windows used for evaluating the algorithm. The <code>NumberOfBacktestWindows</code> from the <code>EvaluationParameters</code> object determines the number of windows in the array.</p>
    pub fn get_test_windows(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::WindowSummary>> {
        &self.test_windows
    }
    /// Consumes the builder and constructs a [`EvaluationResult`](crate::types::EvaluationResult).
    pub fn build(self) -> crate::types::EvaluationResult {
        crate::types::EvaluationResult {
            algorithm_arn: self.algorithm_arn,
            test_windows: self.test_windows,
        }
    }
}
