// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetTemplateOutput {
    /// <p>The ID of the template.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>&gt;The Amazon Resource Name (ARN) of the migration workflow template. The format for an Migration Hub Orchestrator template ARN is <code>arn:aws:migrationhub-orchestrator:region:account:template/template-abcd1234</code>. For more information about ARNs, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html">Amazon Resource Names (ARNs)</a> in the <i>AWS General Reference</i>.</p>
    pub template_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the template.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The time at which the template was last created.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The inputs provided for the creation of the migration workflow.</p>
    pub inputs: ::std::option::Option<::std::vec::Vec<crate::types::TemplateInput>>,
    /// <p>List of AWS services utilized in a migration workflow.</p>
    pub tools: ::std::option::Option<::std::vec::Vec<crate::types::Tool>>,
    /// <p>The time at which the template was last created.</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The owner of the migration workflow template.</p>
    pub owner: ::std::option::Option<::std::string::String>,
    /// <p>The status of the template.</p>
    pub status: ::std::option::Option<crate::types::TemplateStatus>,
    /// <p>The status message of retrieving migration workflow templates.</p>
    pub status_message: ::std::option::Option<::std::string::String>,
    /// <p>The class of the migration workflow template. The available template classes are:</p>
    /// <ul>
    /// <li>
    /// <p>A2C</p></li>
    /// <li>
    /// <p>MGN</p></li>
    /// <li>
    /// <p>SAP_MULTI</p></li>
    /// <li>
    /// <p>SQL_EC2</p></li>
    /// <li>
    /// <p>SQL_RDS</p></li>
    /// <li>
    /// <p>VMIE</p></li>
    /// </ul>
    pub template_class: ::std::option::Option<::std::string::String>,
    /// <p>The tags added to the migration workflow template.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl GetTemplateOutput {
    /// <p>The ID of the template.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>&gt;The Amazon Resource Name (ARN) of the migration workflow template. The format for an Migration Hub Orchestrator template ARN is <code>arn:aws:migrationhub-orchestrator:region:account:template/template-abcd1234</code>. For more information about ARNs, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html">Amazon Resource Names (ARNs)</a> in the <i>AWS General Reference</i>.</p>
    pub fn template_arn(&self) -> ::std::option::Option<&str> {
        self.template_arn.as_deref()
    }
    /// <p>The name of the template.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The time at which the template was last created.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The inputs provided for the creation of the migration workflow.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.inputs.is_none()`.
    pub fn inputs(&self) -> &[crate::types::TemplateInput] {
        self.inputs.as_deref().unwrap_or_default()
    }
    /// <p>List of AWS services utilized in a migration workflow.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tools.is_none()`.
    pub fn tools(&self) -> &[crate::types::Tool] {
        self.tools.as_deref().unwrap_or_default()
    }
    /// <p>The time at which the template was last created.</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>The owner of the migration workflow template.</p>
    pub fn owner(&self) -> ::std::option::Option<&str> {
        self.owner.as_deref()
    }
    /// <p>The status of the template.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::TemplateStatus> {
        self.status.as_ref()
    }
    /// <p>The status message of retrieving migration workflow templates.</p>
    pub fn status_message(&self) -> ::std::option::Option<&str> {
        self.status_message.as_deref()
    }
    /// <p>The class of the migration workflow template. The available template classes are:</p>
    /// <ul>
    /// <li>
    /// <p>A2C</p></li>
    /// <li>
    /// <p>MGN</p></li>
    /// <li>
    /// <p>SAP_MULTI</p></li>
    /// <li>
    /// <p>SQL_EC2</p></li>
    /// <li>
    /// <p>SQL_RDS</p></li>
    /// <li>
    /// <p>VMIE</p></li>
    /// </ul>
    pub fn template_class(&self) -> ::std::option::Option<&str> {
        self.template_class.as_deref()
    }
    /// <p>The tags added to the migration workflow template.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetTemplateOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetTemplateOutput {
    /// Creates a new builder-style object to manufacture [`GetTemplateOutput`](crate::operation::get_template::GetTemplateOutput).
    pub fn builder() -> crate::operation::get_template::builders::GetTemplateOutputBuilder {
        crate::operation::get_template::builders::GetTemplateOutputBuilder::default()
    }
}

/// A builder for [`GetTemplateOutput`](crate::operation::get_template::GetTemplateOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetTemplateOutputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) template_arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) inputs: ::std::option::Option<::std::vec::Vec<crate::types::TemplateInput>>,
    pub(crate) tools: ::std::option::Option<::std::vec::Vec<crate::types::Tool>>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) owner: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::TemplateStatus>,
    pub(crate) status_message: ::std::option::Option<::std::string::String>,
    pub(crate) template_class: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl GetTemplateOutputBuilder {
    /// <p>The ID of the template.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the template.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the template.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>&gt;The Amazon Resource Name (ARN) of the migration workflow template. The format for an Migration Hub Orchestrator template ARN is <code>arn:aws:migrationhub-orchestrator:region:account:template/template-abcd1234</code>. For more information about ARNs, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html">Amazon Resource Names (ARNs)</a> in the <i>AWS General Reference</i>.</p>
    pub fn template_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>&gt;The Amazon Resource Name (ARN) of the migration workflow template. The format for an Migration Hub Orchestrator template ARN is <code>arn:aws:migrationhub-orchestrator:region:account:template/template-abcd1234</code>. For more information about ARNs, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html">Amazon Resource Names (ARNs)</a> in the <i>AWS General Reference</i>.</p>
    pub fn set_template_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_arn = input;
        self
    }
    /// <p>&gt;The Amazon Resource Name (ARN) of the migration workflow template. The format for an Migration Hub Orchestrator template ARN is <code>arn:aws:migrationhub-orchestrator:region:account:template/template-abcd1234</code>. For more information about ARNs, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html">Amazon Resource Names (ARNs)</a> in the <i>AWS General Reference</i>.</p>
    pub fn get_template_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_arn
    }
    /// <p>The name of the template.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the template.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the template.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The time at which the template was last created.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The time at which the template was last created.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The time at which the template was last created.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `inputs`.
    ///
    /// To override the contents of this collection use [`set_inputs`](Self::set_inputs).
    ///
    /// <p>The inputs provided for the creation of the migration workflow.</p>
    pub fn inputs(mut self, input: crate::types::TemplateInput) -> Self {
        let mut v = self.inputs.unwrap_or_default();
        v.push(input);
        self.inputs = ::std::option::Option::Some(v);
        self
    }
    /// <p>The inputs provided for the creation of the migration workflow.</p>
    pub fn set_inputs(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TemplateInput>>) -> Self {
        self.inputs = input;
        self
    }
    /// <p>The inputs provided for the creation of the migration workflow.</p>
    pub fn get_inputs(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TemplateInput>> {
        &self.inputs
    }
    /// Appends an item to `tools`.
    ///
    /// To override the contents of this collection use [`set_tools`](Self::set_tools).
    ///
    /// <p>List of AWS services utilized in a migration workflow.</p>
    pub fn tools(mut self, input: crate::types::Tool) -> Self {
        let mut v = self.tools.unwrap_or_default();
        v.push(input);
        self.tools = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of AWS services utilized in a migration workflow.</p>
    pub fn set_tools(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tool>>) -> Self {
        self.tools = input;
        self
    }
    /// <p>List of AWS services utilized in a migration workflow.</p>
    pub fn get_tools(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tool>> {
        &self.tools
    }
    /// <p>The time at which the template was last created.</p>
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time at which the template was last created.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The time at which the template was last created.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>The owner of the migration workflow template.</p>
    pub fn owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The owner of the migration workflow template.</p>
    pub fn set_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.owner = input;
        self
    }
    /// <p>The owner of the migration workflow template.</p>
    pub fn get_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.owner
    }
    /// <p>The status of the template.</p>
    pub fn status(mut self, input: crate::types::TemplateStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the template.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::TemplateStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the template.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::TemplateStatus> {
        &self.status
    }
    /// <p>The status message of retrieving migration workflow templates.</p>
    pub fn status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status message of retrieving migration workflow templates.</p>
    pub fn set_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_message = input;
        self
    }
    /// <p>The status message of retrieving migration workflow templates.</p>
    pub fn get_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_message
    }
    /// <p>The class of the migration workflow template. The available template classes are:</p>
    /// <ul>
    /// <li>
    /// <p>A2C</p></li>
    /// <li>
    /// <p>MGN</p></li>
    /// <li>
    /// <p>SAP_MULTI</p></li>
    /// <li>
    /// <p>SQL_EC2</p></li>
    /// <li>
    /// <p>SQL_RDS</p></li>
    /// <li>
    /// <p>VMIE</p></li>
    /// </ul>
    pub fn template_class(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_class = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The class of the migration workflow template. The available template classes are:</p>
    /// <ul>
    /// <li>
    /// <p>A2C</p></li>
    /// <li>
    /// <p>MGN</p></li>
    /// <li>
    /// <p>SAP_MULTI</p></li>
    /// <li>
    /// <p>SQL_EC2</p></li>
    /// <li>
    /// <p>SQL_RDS</p></li>
    /// <li>
    /// <p>VMIE</p></li>
    /// </ul>
    pub fn set_template_class(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_class = input;
        self
    }
    /// <p>The class of the migration workflow template. The available template classes are:</p>
    /// <ul>
    /// <li>
    /// <p>A2C</p></li>
    /// <li>
    /// <p>MGN</p></li>
    /// <li>
    /// <p>SAP_MULTI</p></li>
    /// <li>
    /// <p>SQL_EC2</p></li>
    /// <li>
    /// <p>SQL_RDS</p></li>
    /// <li>
    /// <p>VMIE</p></li>
    /// </ul>
    pub fn get_template_class(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_class
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags added to the migration workflow template.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags added to the migration workflow template.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags added to the migration workflow template.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetTemplateOutput`](crate::operation::get_template::GetTemplateOutput).
    pub fn build(self) -> crate::operation::get_template::GetTemplateOutput {
        crate::operation::get_template::GetTemplateOutput {
            id: self.id,
            template_arn: self.template_arn,
            name: self.name,
            description: self.description,
            inputs: self.inputs,
            tools: self.tools,
            creation_time: self.creation_time,
            owner: self.owner,
            status: self.status,
            status_message: self.status_message,
            template_class: self.template_class,
            tags: self.tags,
            _request_id: self._request_id,
        }
    }
}
