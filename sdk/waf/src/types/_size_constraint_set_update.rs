// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <note>
/// <p>This is <b>AWS WAF Classic</b> documentation. For more information, see <a href="https://docs.aws.amazon.com/waf/latest/developerguide/classic-waf-chapter.html">AWS WAF Classic</a> in the developer guide.</p>
/// <p><b>For the latest version of AWS WAF</b>, use the AWS WAFV2 API and see the <a href="https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html">AWS WAF Developer Guide</a>. With the latest version, AWS WAF has a single set of endpoints for regional and global use.</p>
/// </note>
/// <p>Specifies the part of a web request that you want to inspect the size of and indicates whether you want to add the specification to a <code>SizeConstraintSet</code> or delete it from a <code>SizeConstraintSet</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SizeConstraintSetUpdate {
    /// <p>Specify <code>INSERT</code> to add a <code>SizeConstraintSetUpdate</code> to a <code>SizeConstraintSet</code>. Use <code>DELETE</code> to remove a <code>SizeConstraintSetUpdate</code> from a <code>SizeConstraintSet</code>.</p>
    pub action: crate::types::ChangeAction,
    /// <p>Specifies a constraint on the size of a part of the web request. AWS WAF uses the <code>Size</code>, <code>ComparisonOperator</code>, and <code>FieldToMatch</code> to build an expression in the form of "<code>Size</code> <code>ComparisonOperator</code> size in bytes of <code>FieldToMatch</code>". If that expression is true, the <code>SizeConstraint</code> is considered to match.</p>
    pub size_constraint: ::std::option::Option<crate::types::SizeConstraint>,
}
impl SizeConstraintSetUpdate {
    /// <p>Specify <code>INSERT</code> to add a <code>SizeConstraintSetUpdate</code> to a <code>SizeConstraintSet</code>. Use <code>DELETE</code> to remove a <code>SizeConstraintSetUpdate</code> from a <code>SizeConstraintSet</code>.</p>
    pub fn action(&self) -> &crate::types::ChangeAction {
        &self.action
    }
    /// <p>Specifies a constraint on the size of a part of the web request. AWS WAF uses the <code>Size</code>, <code>ComparisonOperator</code>, and <code>FieldToMatch</code> to build an expression in the form of "<code>Size</code> <code>ComparisonOperator</code> size in bytes of <code>FieldToMatch</code>". If that expression is true, the <code>SizeConstraint</code> is considered to match.</p>
    pub fn size_constraint(&self) -> ::std::option::Option<&crate::types::SizeConstraint> {
        self.size_constraint.as_ref()
    }
}
impl SizeConstraintSetUpdate {
    /// Creates a new builder-style object to manufacture [`SizeConstraintSetUpdate`](crate::types::SizeConstraintSetUpdate).
    pub fn builder() -> crate::types::builders::SizeConstraintSetUpdateBuilder {
        crate::types::builders::SizeConstraintSetUpdateBuilder::default()
    }
}

/// A builder for [`SizeConstraintSetUpdate`](crate::types::SizeConstraintSetUpdate).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SizeConstraintSetUpdateBuilder {
    pub(crate) action: ::std::option::Option<crate::types::ChangeAction>,
    pub(crate) size_constraint: ::std::option::Option<crate::types::SizeConstraint>,
}
impl SizeConstraintSetUpdateBuilder {
    /// <p>Specify <code>INSERT</code> to add a <code>SizeConstraintSetUpdate</code> to a <code>SizeConstraintSet</code>. Use <code>DELETE</code> to remove a <code>SizeConstraintSetUpdate</code> from a <code>SizeConstraintSet</code>.</p>
    /// This field is required.
    pub fn action(mut self, input: crate::types::ChangeAction) -> Self {
        self.action = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify <code>INSERT</code> to add a <code>SizeConstraintSetUpdate</code> to a <code>SizeConstraintSet</code>. Use <code>DELETE</code> to remove a <code>SizeConstraintSetUpdate</code> from a <code>SizeConstraintSet</code>.</p>
    pub fn set_action(mut self, input: ::std::option::Option<crate::types::ChangeAction>) -> Self {
        self.action = input;
        self
    }
    /// <p>Specify <code>INSERT</code> to add a <code>SizeConstraintSetUpdate</code> to a <code>SizeConstraintSet</code>. Use <code>DELETE</code> to remove a <code>SizeConstraintSetUpdate</code> from a <code>SizeConstraintSet</code>.</p>
    pub fn get_action(&self) -> &::std::option::Option<crate::types::ChangeAction> {
        &self.action
    }
    /// <p>Specifies a constraint on the size of a part of the web request. AWS WAF uses the <code>Size</code>, <code>ComparisonOperator</code>, and <code>FieldToMatch</code> to build an expression in the form of "<code>Size</code> <code>ComparisonOperator</code> size in bytes of <code>FieldToMatch</code>". If that expression is true, the <code>SizeConstraint</code> is considered to match.</p>
    /// This field is required.
    pub fn size_constraint(mut self, input: crate::types::SizeConstraint) -> Self {
        self.size_constraint = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies a constraint on the size of a part of the web request. AWS WAF uses the <code>Size</code>, <code>ComparisonOperator</code>, and <code>FieldToMatch</code> to build an expression in the form of "<code>Size</code> <code>ComparisonOperator</code> size in bytes of <code>FieldToMatch</code>". If that expression is true, the <code>SizeConstraint</code> is considered to match.</p>
    pub fn set_size_constraint(mut self, input: ::std::option::Option<crate::types::SizeConstraint>) -> Self {
        self.size_constraint = input;
        self
    }
    /// <p>Specifies a constraint on the size of a part of the web request. AWS WAF uses the <code>Size</code>, <code>ComparisonOperator</code>, and <code>FieldToMatch</code> to build an expression in the form of "<code>Size</code> <code>ComparisonOperator</code> size in bytes of <code>FieldToMatch</code>". If that expression is true, the <code>SizeConstraint</code> is considered to match.</p>
    pub fn get_size_constraint(&self) -> &::std::option::Option<crate::types::SizeConstraint> {
        &self.size_constraint
    }
    /// Consumes the builder and constructs a [`SizeConstraintSetUpdate`](crate::types::SizeConstraintSetUpdate).
    /// This method will fail if any of the following fields are not set:
    /// - [`action`](crate::types::builders::SizeConstraintSetUpdateBuilder::action)
    pub fn build(self) -> ::std::result::Result<crate::types::SizeConstraintSetUpdate, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SizeConstraintSetUpdate {
            action: self.action.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "action",
                    "action was not specified but it is required when building SizeConstraintSetUpdate",
                )
            })?,
            size_constraint: self.size_constraint,
        })
    }
}
