// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyDbParameterGroupInput {
    /// <p>The name of the DB parameter group.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>If supplied, must match the name of an existing <code>DBParameterGroup</code>.</p></li>
    /// </ul>
    pub db_parameter_group_name: ::std::option::Option<::std::string::String>,
    /// <p>An array of parameter names, values, and the application methods for the parameter update. At least one parameter name, value, and application method must be supplied; later arguments are optional. A maximum of 20 parameters can be modified in a single request.</p>
    /// <p>Valid Values (for the application method): <code>immediate | pending-reboot</code></p>
    /// <p>You can use the <code>immediate</code> value with dynamic parameters only. You can use the <code>pending-reboot</code> value for both dynamic and static parameters.</p>
    /// <p>When the application method is <code>immediate</code>, changes to dynamic parameters are applied immediately to the DB instances associated with the parameter group.</p>
    /// <p>When the application method is <code>pending-reboot</code>, changes to dynamic and static parameters are applied after a reboot without failover to the DB instances associated with the parameter group.</p><note>
    /// <p>You can't use <code>pending-reboot</code> with dynamic parameters on RDS for SQL Server DB instances. Use <code>immediate</code>.</p>
    /// </note>
    /// <p>For more information on modifying DB parameters, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithParamGroups.html">Working with DB parameter groups</a> in the <i>Amazon RDS User Guide</i>.</p>
    pub parameters: ::std::option::Option<::std::vec::Vec<crate::types::Parameter>>,
}
impl ModifyDbParameterGroupInput {
    /// <p>The name of the DB parameter group.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>If supplied, must match the name of an existing <code>DBParameterGroup</code>.</p></li>
    /// </ul>
    pub fn db_parameter_group_name(&self) -> ::std::option::Option<&str> {
        self.db_parameter_group_name.as_deref()
    }
    /// <p>An array of parameter names, values, and the application methods for the parameter update. At least one parameter name, value, and application method must be supplied; later arguments are optional. A maximum of 20 parameters can be modified in a single request.</p>
    /// <p>Valid Values (for the application method): <code>immediate | pending-reboot</code></p>
    /// <p>You can use the <code>immediate</code> value with dynamic parameters only. You can use the <code>pending-reboot</code> value for both dynamic and static parameters.</p>
    /// <p>When the application method is <code>immediate</code>, changes to dynamic parameters are applied immediately to the DB instances associated with the parameter group.</p>
    /// <p>When the application method is <code>pending-reboot</code>, changes to dynamic and static parameters are applied after a reboot without failover to the DB instances associated with the parameter group.</p><note>
    /// <p>You can't use <code>pending-reboot</code> with dynamic parameters on RDS for SQL Server DB instances. Use <code>immediate</code>.</p>
    /// </note>
    /// <p>For more information on modifying DB parameters, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithParamGroups.html">Working with DB parameter groups</a> in the <i>Amazon RDS User Guide</i>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.parameters.is_none()`.
    pub fn parameters(&self) -> &[crate::types::Parameter] {
        self.parameters.as_deref().unwrap_or_default()
    }
}
impl ModifyDbParameterGroupInput {
    /// Creates a new builder-style object to manufacture [`ModifyDbParameterGroupInput`](crate::operation::modify_db_parameter_group::ModifyDbParameterGroupInput).
    pub fn builder() -> crate::operation::modify_db_parameter_group::builders::ModifyDbParameterGroupInputBuilder {
        crate::operation::modify_db_parameter_group::builders::ModifyDbParameterGroupInputBuilder::default()
    }
}

/// A builder for [`ModifyDbParameterGroupInput`](crate::operation::modify_db_parameter_group::ModifyDbParameterGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyDbParameterGroupInputBuilder {
    pub(crate) db_parameter_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) parameters: ::std::option::Option<::std::vec::Vec<crate::types::Parameter>>,
}
impl ModifyDbParameterGroupInputBuilder {
    /// <p>The name of the DB parameter group.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>If supplied, must match the name of an existing <code>DBParameterGroup</code>.</p></li>
    /// </ul>
    /// This field is required.
    pub fn db_parameter_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.db_parameter_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the DB parameter group.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>If supplied, must match the name of an existing <code>DBParameterGroup</code>.</p></li>
    /// </ul>
    pub fn set_db_parameter_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.db_parameter_group_name = input;
        self
    }
    /// <p>The name of the DB parameter group.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>If supplied, must match the name of an existing <code>DBParameterGroup</code>.</p></li>
    /// </ul>
    pub fn get_db_parameter_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.db_parameter_group_name
    }
    /// Appends an item to `parameters`.
    ///
    /// To override the contents of this collection use [`set_parameters`](Self::set_parameters).
    ///
    /// <p>An array of parameter names, values, and the application methods for the parameter update. At least one parameter name, value, and application method must be supplied; later arguments are optional. A maximum of 20 parameters can be modified in a single request.</p>
    /// <p>Valid Values (for the application method): <code>immediate | pending-reboot</code></p>
    /// <p>You can use the <code>immediate</code> value with dynamic parameters only. You can use the <code>pending-reboot</code> value for both dynamic and static parameters.</p>
    /// <p>When the application method is <code>immediate</code>, changes to dynamic parameters are applied immediately to the DB instances associated with the parameter group.</p>
    /// <p>When the application method is <code>pending-reboot</code>, changes to dynamic and static parameters are applied after a reboot without failover to the DB instances associated with the parameter group.</p><note>
    /// <p>You can't use <code>pending-reboot</code> with dynamic parameters on RDS for SQL Server DB instances. Use <code>immediate</code>.</p>
    /// </note>
    /// <p>For more information on modifying DB parameters, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithParamGroups.html">Working with DB parameter groups</a> in the <i>Amazon RDS User Guide</i>.</p>
    pub fn parameters(mut self, input: crate::types::Parameter) -> Self {
        let mut v = self.parameters.unwrap_or_default();
        v.push(input);
        self.parameters = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of parameter names, values, and the application methods for the parameter update. At least one parameter name, value, and application method must be supplied; later arguments are optional. A maximum of 20 parameters can be modified in a single request.</p>
    /// <p>Valid Values (for the application method): <code>immediate | pending-reboot</code></p>
    /// <p>You can use the <code>immediate</code> value with dynamic parameters only. You can use the <code>pending-reboot</code> value for both dynamic and static parameters.</p>
    /// <p>When the application method is <code>immediate</code>, changes to dynamic parameters are applied immediately to the DB instances associated with the parameter group.</p>
    /// <p>When the application method is <code>pending-reboot</code>, changes to dynamic and static parameters are applied after a reboot without failover to the DB instances associated with the parameter group.</p><note>
    /// <p>You can't use <code>pending-reboot</code> with dynamic parameters on RDS for SQL Server DB instances. Use <code>immediate</code>.</p>
    /// </note>
    /// <p>For more information on modifying DB parameters, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithParamGroups.html">Working with DB parameter groups</a> in the <i>Amazon RDS User Guide</i>.</p>
    pub fn set_parameters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Parameter>>) -> Self {
        self.parameters = input;
        self
    }
    /// <p>An array of parameter names, values, and the application methods for the parameter update. At least one parameter name, value, and application method must be supplied; later arguments are optional. A maximum of 20 parameters can be modified in a single request.</p>
    /// <p>Valid Values (for the application method): <code>immediate | pending-reboot</code></p>
    /// <p>You can use the <code>immediate</code> value with dynamic parameters only. You can use the <code>pending-reboot</code> value for both dynamic and static parameters.</p>
    /// <p>When the application method is <code>immediate</code>, changes to dynamic parameters are applied immediately to the DB instances associated with the parameter group.</p>
    /// <p>When the application method is <code>pending-reboot</code>, changes to dynamic and static parameters are applied after a reboot without failover to the DB instances associated with the parameter group.</p><note>
    /// <p>You can't use <code>pending-reboot</code> with dynamic parameters on RDS for SQL Server DB instances. Use <code>immediate</code>.</p>
    /// </note>
    /// <p>For more information on modifying DB parameters, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithParamGroups.html">Working with DB parameter groups</a> in the <i>Amazon RDS User Guide</i>.</p>
    pub fn get_parameters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Parameter>> {
        &self.parameters
    }
    /// Consumes the builder and constructs a [`ModifyDbParameterGroupInput`](crate::operation::modify_db_parameter_group::ModifyDbParameterGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::modify_db_parameter_group::ModifyDbParameterGroupInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::modify_db_parameter_group::ModifyDbParameterGroupInput {
            db_parameter_group_name: self.db_parameter_group_name,
            parameters: self.parameters,
        })
    }
}
