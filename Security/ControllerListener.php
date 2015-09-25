<?php
namespace Lsw\SecureControllerBundle\Security;

use Symfony\Component\HttpKernel\Event\FilterControllerEvent;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Util\ClassUtils;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Core\Exception\AuthenticationCredentialsNotFoundException;
use Doctrine\Common\Annotations\Reader;
use Lsw\SecureControllerBundle\Annotation\Secure;

class ControllerListener
{
    private $annotationReader;
    private $securityContext;
    private $router;

    public function __construct(
        Reader $annotationReader,
        SecurityContextInterface $securityContext,
        RouterInterface $router)
    {
        $this->annotationReader = $annotationReader;
        $this->securityContext  = $securityContext;
        $this->router           = $router;
    }

    public function onKernelController(FilterControllerEvent $event)
    {
        try {
            $route = $this->router->match($event->getRequest()->getPathInfo());
        } catch (\Exception $e) {
            //Suppress 404s
        }
        if (isset($route['_controller']) && strpos($route['_controller'], 'BackendBundle') !== false) {
            if (!$this->securityContext->isGranted('ROLE_ADMIN')) {
                throw new AccessDeniedException(
                    'Current user is not granted required role "' . $role . '".'
                );
            }
        }

        $controller = $event->getController();

        list($object, $method) = $controller;

        // the controller could be a proxy, e.g. when using the JMSSecurityExtraBundle or JMSDiExtraBundle
        $className = ClassUtils::getRealClass($object);

        $reflectionClass  = new \ReflectionClass($className);
        $reflectionMethod = $reflectionClass->getMethod($method);

        $classAnnotations   = $this->annotationReader->getClassAnnotations($reflectionClass);
        $methodsAnnotations = $this->annotationReader->getMethodAnnotations($reflectionMethod);

        $allAnnotations = array_merge($classAnnotations, $methodsAnnotations);

        $secureAnnotations = array_filter($allAnnotations,
            function ($annotation) {
                return $annotation instanceof Secure;
            }
        );

        foreach ($secureAnnotations as $secureAnnotation) {
            if (!$this->securityContext->getToken()) {
                $filename = $reflectionClass->getFileName();
                throw new AuthenticationCredentialsNotFoundException(
                    '@Secure(...) annotation found without firewall on "' . $method . '" in "' . $filename . '"'
                );
            }
            $roles = explode(',', $secureAnnotation->roles);
            foreach ($roles as $role) {
                $role = trim($role);

                if (!$role) {
                    continue;
                }
                if (!$this->securityContext->isGranted($role)) {
                    throw new AccessDeniedException(
                        'Current user is not granted required role "' . $role . '".'
                    );
                }
            }
        }
    }
}