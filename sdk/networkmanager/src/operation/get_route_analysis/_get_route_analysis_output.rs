// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetRouteAnalysisOutput {
    /// <p>The route analysis.</p>
    pub route_analysis: ::std::option::Option<crate::types::RouteAnalysis>,
    _request_id: Option<String>,
}
impl GetRouteAnalysisOutput {
    /// <p>The route analysis.</p>
    pub fn route_analysis(&self) -> ::std::option::Option<&crate::types::RouteAnalysis> {
        self.route_analysis.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetRouteAnalysisOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetRouteAnalysisOutput {
    /// Creates a new builder-style object to manufacture [`GetRouteAnalysisOutput`](crate::operation::get_route_analysis::GetRouteAnalysisOutput).
    pub fn builder() -> crate::operation::get_route_analysis::builders::GetRouteAnalysisOutputBuilder {
        crate::operation::get_route_analysis::builders::GetRouteAnalysisOutputBuilder::default()
    }
}

/// A builder for [`GetRouteAnalysisOutput`](crate::operation::get_route_analysis::GetRouteAnalysisOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetRouteAnalysisOutputBuilder {
    pub(crate) route_analysis: ::std::option::Option<crate::types::RouteAnalysis>,
    _request_id: Option<String>,
}
impl GetRouteAnalysisOutputBuilder {
    /// <p>The route analysis.</p>
    pub fn route_analysis(mut self, input: crate::types::RouteAnalysis) -> Self {
        self.route_analysis = ::std::option::Option::Some(input);
        self
    }
    /// <p>The route analysis.</p>
    pub fn set_route_analysis(mut self, input: ::std::option::Option<crate::types::RouteAnalysis>) -> Self {
        self.route_analysis = input;
        self
    }
    /// <p>The route analysis.</p>
    pub fn get_route_analysis(&self) -> &::std::option::Option<crate::types::RouteAnalysis> {
        &self.route_analysis
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetRouteAnalysisOutput`](crate::operation::get_route_analysis::GetRouteAnalysisOutput).
    pub fn build(self) -> crate::operation::get_route_analysis::GetRouteAnalysisOutput {
        crate::operation::get_route_analysis::GetRouteAnalysisOutput {
            route_analysis: self.route_analysis,
            _request_id: self._request_id,
        }
    }
}
