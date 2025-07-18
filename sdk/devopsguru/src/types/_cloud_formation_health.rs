// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the health of Amazon Web Services resources in your account that are specified by an Amazon Web Services CloudFormation stack.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CloudFormationHealth {
    /// <p>The name of the CloudFormation stack.</p>
    pub stack_name: ::std::option::Option<::std::string::String>,
    /// <p>Information about the health of the Amazon Web Services resources in your account that are specified by an Amazon Web Services CloudFormation stack, including the number of open proactive, open reactive insights, and the Mean Time to Recover (MTTR) of closed insights.</p>
    pub insight: ::std::option::Option<crate::types::InsightHealth>,
    /// <p>Number of resources that DevOps Guru is monitoring in your account that are specified by an Amazon Web Services CloudFormation stack.</p>
    pub analyzed_resource_count: ::std::option::Option<i64>,
}
impl CloudFormationHealth {
    /// <p>The name of the CloudFormation stack.</p>
    pub fn stack_name(&self) -> ::std::option::Option<&str> {
        self.stack_name.as_deref()
    }
    /// <p>Information about the health of the Amazon Web Services resources in your account that are specified by an Amazon Web Services CloudFormation stack, including the number of open proactive, open reactive insights, and the Mean Time to Recover (MTTR) of closed insights.</p>
    pub fn insight(&self) -> ::std::option::Option<&crate::types::InsightHealth> {
        self.insight.as_ref()
    }
    /// <p>Number of resources that DevOps Guru is monitoring in your account that are specified by an Amazon Web Services CloudFormation stack.</p>
    pub fn analyzed_resource_count(&self) -> ::std::option::Option<i64> {
        self.analyzed_resource_count
    }
}
impl CloudFormationHealth {
    /// Creates a new builder-style object to manufacture [`CloudFormationHealth`](crate::types::CloudFormationHealth).
    pub fn builder() -> crate::types::builders::CloudFormationHealthBuilder {
        crate::types::builders::CloudFormationHealthBuilder::default()
    }
}

/// A builder for [`CloudFormationHealth`](crate::types::CloudFormationHealth).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CloudFormationHealthBuilder {
    pub(crate) stack_name: ::std::option::Option<::std::string::String>,
    pub(crate) insight: ::std::option::Option<crate::types::InsightHealth>,
    pub(crate) analyzed_resource_count: ::std::option::Option<i64>,
}
impl CloudFormationHealthBuilder {
    /// <p>The name of the CloudFormation stack.</p>
    pub fn stack_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stack_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the CloudFormation stack.</p>
    pub fn set_stack_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stack_name = input;
        self
    }
    /// <p>The name of the CloudFormation stack.</p>
    pub fn get_stack_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.stack_name
    }
    /// <p>Information about the health of the Amazon Web Services resources in your account that are specified by an Amazon Web Services CloudFormation stack, including the number of open proactive, open reactive insights, and the Mean Time to Recover (MTTR) of closed insights.</p>
    pub fn insight(mut self, input: crate::types::InsightHealth) -> Self {
        self.insight = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the health of the Amazon Web Services resources in your account that are specified by an Amazon Web Services CloudFormation stack, including the number of open proactive, open reactive insights, and the Mean Time to Recover (MTTR) of closed insights.</p>
    pub fn set_insight(mut self, input: ::std::option::Option<crate::types::InsightHealth>) -> Self {
        self.insight = input;
        self
    }
    /// <p>Information about the health of the Amazon Web Services resources in your account that are specified by an Amazon Web Services CloudFormation stack, including the number of open proactive, open reactive insights, and the Mean Time to Recover (MTTR) of closed insights.</p>
    pub fn get_insight(&self) -> &::std::option::Option<crate::types::InsightHealth> {
        &self.insight
    }
    /// <p>Number of resources that DevOps Guru is monitoring in your account that are specified by an Amazon Web Services CloudFormation stack.</p>
    pub fn analyzed_resource_count(mut self, input: i64) -> Self {
        self.analyzed_resource_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>Number of resources that DevOps Guru is monitoring in your account that are specified by an Amazon Web Services CloudFormation stack.</p>
    pub fn set_analyzed_resource_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.analyzed_resource_count = input;
        self
    }
    /// <p>Number of resources that DevOps Guru is monitoring in your account that are specified by an Amazon Web Services CloudFormation stack.</p>
    pub fn get_analyzed_resource_count(&self) -> &::std::option::Option<i64> {
        &self.analyzed_resource_count
    }
    /// Consumes the builder and constructs a [`CloudFormationHealth`](crate::types::CloudFormationHealth).
    pub fn build(self) -> crate::types::CloudFormationHealth {
        crate::types::CloudFormationHealth {
            stack_name: self.stack_name,
            insight: self.insight,
            analyzed_resource_count: self.analyzed_resource_count,
        }
    }
}
