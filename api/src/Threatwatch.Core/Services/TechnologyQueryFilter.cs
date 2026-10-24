using System.Linq.Expressions;
using Threatwatch.Core.Entities;
using Threatwatch.Core.Enums;

namespace Threatwatch.Core.Services;

public static class TechnologyQueryFilter
{
    public static IQueryable<Vulnerability> WhereMatchesAny(
        this IQueryable<Vulnerability> query,
        IReadOnlyList<Technology> technologies)
    {
        if (technologies.Count == 0)
        {
            return query.Where(_ => false);
        }

        Expression<Func<Vulnerability, bool>>? combined = null;
        foreach (var technology in technologies)
        {
            var predicate = PredicateFor(technology);
            combined = combined is null ? predicate : Or(combined, predicate);
        }

        return query.Where(combined!);
    }

    public static Expression<Func<Vulnerability, bool>> PredicateFor(Technology technology)
    {
        if (TechnologyPackageMatcher.IsEcosystemWide(technology))
        {
            var eco = technology.Ecosystem!.Value;
            return v => v.AffectedPackages.Any(p => p.Ecosystem == eco);
        }

        var tokens = TechnologyPackageMatcher.Names(technology)
            .Select(name => name.ToLowerInvariant())
            .ToArray();
        var scoped = technology.Ecosystem;
        Expression<Func<Vulnerability, bool>> predicate = v => v.AffectedPackages.Any(p =>
            (scoped == null || p.Ecosystem == scoped)
            && (tokens.Contains(p.PackageName.ToLower())
                || tokens.Contains(p.DisplayName.ToLower())));

        foreach (var token in tokens.Where(t => t.Length >= TechnologyPackageMatcher.MinFuzzyTokenLength))
        {
            predicate = Or(predicate, FuzzyPredicate(scoped, token));
        }

        return predicate;
    }

    private static Expression<Func<Vulnerability, bool>> FuzzyPredicate(Ecosystem? scoped, string token)
    {
        var dash = token + "-";
        var slash = token + "/";
        var atSlash = "@" + token + "/";
        var trailing = "/" + token;
        return v => v.AffectedPackages.Any(p =>
            (scoped == null || p.Ecosystem == scoped)
            && (p.PackageName.ToLower().StartsWith(dash)
                || p.PackageName.ToLower().StartsWith(slash)
                || p.PackageName.ToLower().StartsWith(atSlash)
                || p.PackageName.ToLower().EndsWith(trailing)
                || p.DisplayName.ToLower().StartsWith(dash)
                || p.DisplayName.ToLower().StartsWith(slash)
                || p.DisplayName.ToLower().StartsWith(atSlash)
                || p.DisplayName.ToLower().EndsWith(trailing)));
    }

    private static Expression<Func<T, bool>> Or<T>(
        Expression<Func<T, bool>> left,
        Expression<Func<T, bool>> right)
    {
        var parameter = Expression.Parameter(typeof(T), "v");
        var leftBody = new ReplaceParameter(left.Parameters[0], parameter).Visit(left.Body)!;
        var rightBody = new ReplaceParameter(right.Parameters[0], parameter).Visit(right.Body)!;
        return Expression.Lambda<Func<T, bool>>(Expression.OrElse(leftBody, rightBody), parameter);
    }

    private sealed class ReplaceParameter(ParameterExpression from, ParameterExpression to) : ExpressionVisitor
    {
        protected override Expression VisitParameter(ParameterExpression node) =>
            node == from ? to : base.VisitParameter(node);
    }
}
