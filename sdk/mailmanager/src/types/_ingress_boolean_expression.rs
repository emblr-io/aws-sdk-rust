// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The structure for a boolean condition matching on the incoming mail.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IngressBooleanExpression {
    /// <p>The operand on which to perform a boolean condition operation.</p>
    pub evaluate: ::std::option::Option<crate::types::IngressBooleanToEvaluate>,
    /// <p>The matching operator for a boolean condition expression.</p>
    pub operator: crate::types::IngressBooleanOperator,
}
impl IngressBooleanExpression {
    /// <p>The operand on which to perform a boolean condition operation.</p>
    pub fn evaluate(&self) -> ::std::option::Option<&crate::types::IngressBooleanToEvaluate> {
        self.evaluate.as_ref()
    }
    /// <p>The matching operator for a boolean condition expression.</p>
    pub fn operator(&self) -> &crate::types::IngressBooleanOperator {
        &self.operator
    }
}
impl IngressBooleanExpression {
    /// Creates a new builder-style object to manufacture [`IngressBooleanExpression`](crate::types::IngressBooleanExpression).
    pub fn builder() -> crate::types::builders::IngressBooleanExpressionBuilder {
        crate::types::builders::IngressBooleanExpressionBuilder::default()
    }
}

/// A builder for [`IngressBooleanExpression`](crate::types::IngressBooleanExpression).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IngressBooleanExpressionBuilder {
    pub(crate) evaluate: ::std::option::Option<crate::types::IngressBooleanToEvaluate>,
    pub(crate) operator: ::std::option::Option<crate::types::IngressBooleanOperator>,
}
impl IngressBooleanExpressionBuilder {
    /// <p>The operand on which to perform a boolean condition operation.</p>
    /// This field is required.
    pub fn evaluate(mut self, input: crate::types::IngressBooleanToEvaluate) -> Self {
        self.evaluate = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operand on which to perform a boolean condition operation.</p>
    pub fn set_evaluate(mut self, input: ::std::option::Option<crate::types::IngressBooleanToEvaluate>) -> Self {
        self.evaluate = input;
        self
    }
    /// <p>The operand on which to perform a boolean condition operation.</p>
    pub fn get_evaluate(&self) -> &::std::option::Option<crate::types::IngressBooleanToEvaluate> {
        &self.evaluate
    }
    /// <p>The matching operator for a boolean condition expression.</p>
    /// This field is required.
    pub fn operator(mut self, input: crate::types::IngressBooleanOperator) -> Self {
        self.operator = ::std::option::Option::Some(input);
        self
    }
    /// <p>The matching operator for a boolean condition expression.</p>
    pub fn set_operator(mut self, input: ::std::option::Option<crate::types::IngressBooleanOperator>) -> Self {
        self.operator = input;
        self
    }
    /// <p>The matching operator for a boolean condition expression.</p>
    pub fn get_operator(&self) -> &::std::option::Option<crate::types::IngressBooleanOperator> {
        &self.operator
    }
    /// Consumes the builder and constructs a [`IngressBooleanExpression`](crate::types::IngressBooleanExpression).
    /// This method will fail if any of the following fields are not set:
    /// - [`operator`](crate::types::builders::IngressBooleanExpressionBuilder::operator)
    pub fn build(self) -> ::std::result::Result<crate::types::IngressBooleanExpression, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::IngressBooleanExpression {
            evaluate: self.evaluate,
            operator: self.operator.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "operator",
                    "operator was not specified but it is required when building IngressBooleanExpression",
                )
            })?,
        })
    }
}
