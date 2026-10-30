using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Npgsql;

namespace Rowstile.AspNetCore;

/// <summary>What <see cref="RowstileServices.AddRowstile"/> is told.</summary>
public sealed class RowstileOptions
{
    /// <summary>
    /// Who a request acts for, from the request (its session, its token: <c>context.User</c> once the app's
    /// authentication ran); null: nobody, who sees only what <c>anyone</c> may. Left unset, requests act for whoever
    /// the code around them does.
    /// </summary>
    public Func<HttpContext, Principal?>? User { get; set; }

    /// <summary>
    /// The app role's connection string: given, <see cref="RowstileServices.AddRowstile"/> builds the services'
    /// <see cref="NpgsqlDataSource"/> from it, with Npgsql's <c>Include Error Detail</c> on, so a refused write says
    /// why (the database's DETAIL holds the reasons, which Npgsql hides otherwise). Left unset, the app registers its
    /// own data source, and sets that itself.
    /// </summary>
    public string? ConnectionString { get; set; }

    /// <summary>Whether the app refuses to start on a connection that skips row-level security (yes, unless set to false).</summary>
    public bool CheckConnection { get; set; } = true;

    /// <summary>The connections checked at start: the <see cref="NpgsqlDataSource"/> the services hold, unless this gives another.</summary>
    public Func<IServiceProvider, NpgsqlDataSource>? DataSource { get; set; }
}

/// <summary>
/// rowstile with ASP.NET Core:
/// <code>
/// builder.Services.AddRowstile(o =>
/// {
///     o.ConnectionString = url;                              // the NpgsqlDataSource the services hold
///     o.User = SessionUser;                                  // SessionUser(context): its user, or null for nobody
/// });
/// var app = builder.Build();
/// app.UseRowstile();                                         // before the endpoints
/// </code>
/// Each request acts for <c>User(context)</c>, so every transaction it begins signs in as them (EF Core's, with
/// <c>UseRowstile()</c> on the context's options; Npgsql's, with <c>BeginSignedInAsync</c>). A refused write
/// answers 403 with the reason (an RFC 9457 problem body), a row the user can't see 404, and a call the database turns
/// down that is no refusal as its code's page says, with its words: a login refused or a call that needs someone signed
/// in 401 (AZ703, AZ714), something it names that isn't there 404 (AZ708), an argument missing or wrong 400 (AZ710), a
/// move inside itself 409 (AZ713). An update of EF Core's the rules allow that matched no row (the row changed since it
/// was read: a concurrency token) answers 409. At start the app refuses to run on a connection that skips row-level
/// security (<c>authz.connection_check()</c>).
/// </summary>
public static class RowstileServices
{
    /// <summary>
    /// The options the middleware reads, the data source if a connection string is given, and the start-up check (see
    /// <see cref="RowstileServices"/>).
    /// </summary>
    public static IServiceCollection AddRowstile(this IServiceCollection services, Action<RowstileOptions>? configure = null)
    {
        var options = new RowstileOptions();
        configure?.Invoke(options);
        services.AddSingleton(options);
        if (options.ConnectionString is { } connectionString)
        {
            var withDetail = new NpgsqlConnectionStringBuilder(connectionString) { IncludeErrorDetail = true };
            services.AddSingleton(_ => NpgsqlDataSource.Create(withDetail));
        }
        if (options.CheckConnection)
        {
            services.AddHostedService<ConnectionCheck>();
        }
        return services;
    }

    /// <summary>The middleware: each request acts for its user, and the database's answers become problem bodies.</summary>
    public static IApplicationBuilder UseRowstile(this IApplicationBuilder app) => app.UseMiddleware<RowstileMiddleware>();
}

internal sealed class RowstileMiddleware(RequestDelegate next, RowstileOptions options)
{
    public async Task InvokeAsync(HttpContext context)
    {
        using var acting = options.User is null ? null : Acting.As(options.User(context) ?? Principal.Nobody);
        try
        {
            await next(context).ConfigureAwait(false);
        }
        catch (Exception e) when (!context.Response.HasStarted && Errors.ProblemOf(e) is { } problem)
        {
            await Write(context, problem).ConfigureAwait(false);
        }
        catch (Exception e) when (Errors.IsNotSignedIn(e))
        {
            // the app's bug, not the user's doing: a 500 that says what
            throw new NotSignedInException(
                "a query ran in a transaction nobody signed in to: every transaction must begin with authz.act_as() "
                    + "(UseRowstile() on the DbContext's options does it, and BeginSignedInAsync on an Npgsql connection)",
                e
            );
        }
    }

    private static Task Write(HttpContext context, Problem problem)
    {
        var details = new ProblemDetails
        {
            Type = problem.Type,
            Title = problem.Title,
            Status = problem.Status,
            Detail = problem.Detail,
        };
        foreach (var (key, value) in problem.Extensions)
        {
            details.Extensions[key] = value;
        }
        context.Response.StatusCode = problem.Status;
        return context.Response.WriteAsJsonAsync(details, options: null, "application/problem+json", context.RequestAborted);
    }
}

/// <summary>At start, before the app takes a request: refuses a connection that skips row-level security.</summary>
internal sealed class ConnectionCheck(RowstileOptions options, IServiceProvider services) : IHostedService
{
    public Task StartAsync(CancellationToken cancellationToken)
    {
        var dataSource = options.DataSource is { } given ? given(services) : services.GetRequiredService<NpgsqlDataSource>();
        return dataSource.CheckAsync(cancellationToken);
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
