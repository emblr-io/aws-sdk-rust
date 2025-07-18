// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
impl super::Client {
    /// Constructs a fluent builder for the [`GetDbServer`](crate::operation::get_db_server::builders::GetDbServerFluentBuilder) operation.
    ///
    /// - The fluent builder is configurable:
    ///   - [`cloud_exadata_infrastructure_id(impl Into<String>)`](crate::operation::get_db_server::builders::GetDbServerFluentBuilder::cloud_exadata_infrastructure_id) / [`set_cloud_exadata_infrastructure_id(Option<String>)`](crate::operation::get_db_server::builders::GetDbServerFluentBuilder::set_cloud_exadata_infrastructure_id):<br>required: **true**<br><p>The unique identifier of the Oracle Exadata infrastructure that contains the database server.</p><br>
    ///   - [`db_server_id(impl Into<String>)`](crate::operation::get_db_server::builders::GetDbServerFluentBuilder::db_server_id) / [`set_db_server_id(Option<String>)`](crate::operation::get_db_server::builders::GetDbServerFluentBuilder::set_db_server_id):<br>required: **true**<br><p>The unique identifier of the database server to retrieve information about.</p><br>
    /// - On success, responds with [`GetDbServerOutput`](crate::operation::get_db_server::GetDbServerOutput) with field(s):
    ///   - [`db_server(Option<DbServer>)`](crate::operation::get_db_server::GetDbServerOutput::db_server): <p>The details of the requested database server.</p>
    /// - On failure, responds with [`SdkError<GetDbServerError>`](crate::operation::get_db_server::GetDbServerError)
    pub fn get_db_server(&self) -> crate::operation::get_db_server::builders::GetDbServerFluentBuilder {
        crate::operation::get_db_server::builders::GetDbServerFluentBuilder::new(self.handle.clone())
    }
}
