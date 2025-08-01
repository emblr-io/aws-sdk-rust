// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This output contains the list of steps returned in reverse order. This means that the last step is the first element in the list.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListStepsOutput {
    /// <p>The filtered list of steps for the cluster.</p>
    pub steps: ::std::option::Option<::std::vec::Vec<crate::types::StepSummary>>,
    /// <p>The maximum number of steps that a single <code>ListSteps</code> action returns is 50. To return a longer list of steps, use multiple <code>ListSteps</code> actions along with the <code>Marker</code> parameter, which is a pagination token that indicates the next set of results to retrieve.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListStepsOutput {
    /// <p>The filtered list of steps for the cluster.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.steps.is_none()`.
    pub fn steps(&self) -> &[crate::types::StepSummary] {
        self.steps.as_deref().unwrap_or_default()
    }
    /// <p>The maximum number of steps that a single <code>ListSteps</code> action returns is 50. To return a longer list of steps, use multiple <code>ListSteps</code> actions along with the <code>Marker</code> parameter, which is a pagination token that indicates the next set of results to retrieve.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListStepsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListStepsOutput {
    /// Creates a new builder-style object to manufacture [`ListStepsOutput`](crate::operation::list_steps::ListStepsOutput).
    pub fn builder() -> crate::operation::list_steps::builders::ListStepsOutputBuilder {
        crate::operation::list_steps::builders::ListStepsOutputBuilder::default()
    }
}

/// A builder for [`ListStepsOutput`](crate::operation::list_steps::ListStepsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListStepsOutputBuilder {
    pub(crate) steps: ::std::option::Option<::std::vec::Vec<crate::types::StepSummary>>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListStepsOutputBuilder {
    /// Appends an item to `steps`.
    ///
    /// To override the contents of this collection use [`set_steps`](Self::set_steps).
    ///
    /// <p>The filtered list of steps for the cluster.</p>
    pub fn steps(mut self, input: crate::types::StepSummary) -> Self {
        let mut v = self.steps.unwrap_or_default();
        v.push(input);
        self.steps = ::std::option::Option::Some(v);
        self
    }
    /// <p>The filtered list of steps for the cluster.</p>
    pub fn set_steps(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::StepSummary>>) -> Self {
        self.steps = input;
        self
    }
    /// <p>The filtered list of steps for the cluster.</p>
    pub fn get_steps(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::StepSummary>> {
        &self.steps
    }
    /// <p>The maximum number of steps that a single <code>ListSteps</code> action returns is 50. To return a longer list of steps, use multiple <code>ListSteps</code> actions along with the <code>Marker</code> parameter, which is a pagination token that indicates the next set of results to retrieve.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The maximum number of steps that a single <code>ListSteps</code> action returns is 50. To return a longer list of steps, use multiple <code>ListSteps</code> actions along with the <code>Marker</code> parameter, which is a pagination token that indicates the next set of results to retrieve.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>The maximum number of steps that a single <code>ListSteps</code> action returns is 50. To return a longer list of steps, use multiple <code>ListSteps</code> actions along with the <code>Marker</code> parameter, which is a pagination token that indicates the next set of results to retrieve.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListStepsOutput`](crate::operation::list_steps::ListStepsOutput).
    pub fn build(self) -> crate::operation::list_steps::ListStepsOutput {
        crate::operation::list_steps::ListStepsOutput {
            steps: self.steps,
            marker: self.marker,
            _request_id: self._request_id,
        }
    }
}
